from __future__ import annotations

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth.dependencies import nginx_proxied_auth
from ..schemas.management import (
    GroupCreateRequest,
    GroupDeleteResponse,
    GroupListResponse,
    GroupSummary,
    HumanUserRequest,
    M2MAccountRequest,
    UserDeleteResponse,
    UserListResponse,
    UserSummary,
)
from ..services import scope_service
from ..utils.iam_manager import get_iam_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/management", tags=["Management API"])

AUTH_PROVIDER: str = os.environ.get("AUTH_PROVIDER", "keycloak")


def _translate_iam_error(exc: Exception) -> HTTPException:
    """
    Map IAM admin errors to HTTP responses.

    Works for both Keycloak and Entra ID error messages.

    Args:
        exc: The exception from IAM operations

    Returns:
        HTTPException with appropriate status code
    """
    detail = str(exc)
    lowered = detail.lower()
    status_code = status.HTTP_502_BAD_GATEWAY

    if any(keyword in lowered for keyword in ("already exists", "not found", "provided")):
        status_code = status.HTTP_400_BAD_REQUEST

    return HTTPException(status_code=status_code, detail=detail)


def _require_admin(user_context: dict) -> None:
    """
    Verify user has admin permissions.

    Args:
        user_context: User context from authentication

    Raises:
        HTTPException: If user is not an admin
    """
    if not user_context.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator permissions are required for this operation",
        )


@router.get("/iam/users", response_model=UserListResponse)
async def management_list_users(
    search: str | None = None,
    limit: int = 500,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """List users from the configured identity provider (admin only)."""
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        raw_users = await iam.list_users(search=search, max_results=limit)
    except Exception as exc:
        raise _translate_iam_error(exc) from exc

    summaries = [
        UserSummary(
            id=user.get("id", ""),
            username=user.get("username", ""),
            email=user.get("email"),
            firstName=user.get("firstName"),
            lastName=user.get("lastName"),
            enabled=user.get("enabled", True),
            groups=user.get("groups", []),
        )
        for user in raw_users
    ]
    return UserListResponse(users=summaries, total=len(summaries))


@router.post("/iam/users/m2m")
async def management_create_m2m_user(
    payload: M2MAccountRequest,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """Create a service account client and return its credentials (admin only)."""
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        result = await iam.create_service_account(
            client_id=payload.name,
            groups=payload.groups,
            description=payload.description,
        )
    except Exception as exc:
        raise _translate_iam_error(exc) from exc

    return result


@router.post("/iam/users/human")
async def management_create_human_user(
    payload: HumanUserRequest,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """Create a human user and assign groups (admin only)."""
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        user_doc = await iam.create_human_user(
            username=payload.username,
            email=payload.email,
            first_name=payload.first_name,
            last_name=payload.last_name,
            groups=payload.groups,
            password=payload.password,
        )
    except Exception as exc:
        raise _translate_iam_error(exc) from exc

    return UserSummary(
        id=user_doc.get("id", ""),
        username=user_doc.get("username", payload.username),
        email=user_doc.get("email"),
        firstName=user_doc.get("firstName"),
        lastName=user_doc.get("lastName"),
        enabled=user_doc.get("enabled", True),
        groups=user_doc.get("groups", payload.groups),
    )


@router.delete("/iam/users/{username}", response_model=UserDeleteResponse)
async def management_delete_user(
    username: str,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """Delete a user by username (admin only)."""
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        await iam.delete_user(username=username)
    except Exception as exc:
        raise _translate_iam_error(exc) from exc

    return UserDeleteResponse(username=username)


@router.get("/iam/groups", response_model=GroupListResponse)
async def management_list_groups(
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """List IAM groups from the configured identity provider (admin only)."""
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        raw_groups = await iam.list_groups()
        summaries = [
            GroupSummary(
                id=group.get("id", ""),
                name=group.get("name", ""),
                path=group.get("path", ""),
                attributes=group.get("attributes"),
            )
            for group in raw_groups
        ]
        return GroupListResponse(groups=summaries, total=len(summaries))
    except Exception as exc:
        logger.error("Failed to list IAM groups: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to list IAM groups",
        ) from exc


@router.post("/iam/groups", response_model=GroupSummary)
async def management_create_group(
    payload: GroupCreateRequest,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """
    Create a new group in the identity provider and MongoDB (admin only).

    This creates the group in both:
    1. The configured identity provider (Keycloak or Entra ID)
    2. MongoDB scopes collection for authorization
    """
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        # Step 1: Create group in identity provider
        result = await iam.create_group(
            group_name=payload.name, description=payload.description or ""
        )

        # Step 2: Determine group mapping identifier
        # For Keycloak: use group name
        # For Entra ID: use the Object ID (GUID) returned from Graph API
        provider = AUTH_PROVIDER.lower()
        if provider == "entra":
            # Entra ID tokens contain group Object IDs, not names
            group_mapping_id = result.get("id", payload.name)
        else:
            # Keycloak tokens contain group names
            group_mapping_id = payload.name

        # Step 3: Create in MongoDB scopes collection
        import_success = await scope_service.import_group(
            scope_name=payload.name,
            description=payload.description or "",
            group_mappings=[group_mapping_id],
            server_access=[],
            ui_permissions={},
        )

        if not import_success:
            logger.warning("Group created in IdP but failed to create in MongoDB: %s", payload.name)

        return GroupSummary(
            id=result.get("id", ""),
            name=result.get("name", ""),
            path=result.get("path", ""),
            attributes=result.get("attributes"),
        )

    except Exception as exc:
        logger.error("Failed to create group: %s", exc)
        detail = str(exc).lower()

        if "already exists" in detail:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        raise _translate_iam_error(exc) from exc


@router.delete("/iam/groups/{group_name}", response_model=GroupDeleteResponse)
async def management_delete_group(
    group_name: str,
    user_context: Annotated[dict, Depends(nginx_proxied_auth)] = None,
):
    """
    Delete a group from the identity provider and MongoDB (admin only).

    This deletes the group from both:
    1. The configured identity provider (Keycloak or Entra ID)
    2. MongoDB scopes collection
    """
    _require_admin(user_context)

    iam = get_iam_manager()

    try:
        # Step 1: Delete from identity provider
        await iam.delete_group(group_name=group_name)

        # Step 2: Delete from MongoDB scopes collection
        delete_success = await scope_service.delete_group(
            group_name=group_name, remove_from_mappings=True
        )

        if not delete_success:
            logger.warning(
                "Group deleted from IdP but failed to delete from MongoDB: %s",
                group_name,
            )

        return GroupDeleteResponse(name=group_name)

    except Exception as exc:
        logger.error("Failed to delete group: %s", exc)
        detail = str(exc).lower()

        if "not found" in detail:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Group '{group_name}' not found",
            ) from exc

        raise _translate_iam_error(exc) from exc
