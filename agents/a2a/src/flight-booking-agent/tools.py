"""Tools for Flight Booking Agent - Direct SQLite operations for booking management."""

import json
import logging
from typing import Any

from dependencies import get_db_manager
from strands import tool

# Configure logging with basicConfig
logging.basicConfig(
    level=logging.INFO,  # Set the log level to INFO
    # Define log message format
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)


@tool
def check_availability(
    flight_id: int,
) -> str:
    """Check seat availability for a specific flight."""
    logger.info(f"Tool called: check_availability(flight_id={flight_id})")
    try:
        availability = get_db_manager().get_flight_availability(flight_id)

        if not availability:
            error_msg = f"Flight with ID {flight_id} not found"
            logger.warning(error_msg)
            return json.dumps({"error": error_msg})

        logger.debug(f"Availability result:\n{json.dumps(availability, indent=2)}")
        return json.dumps(availability, indent=2)

    except Exception as e:
        logger.exception(f"Database error in check_availability: {e}")
        return json.dumps({"error": "An internal database error occurred"})


@tool
def reserve_flight(
    flight_id: int,
    passengers: list[dict[str, str]],
    requested_seats: list[str] | None = None,
) -> str:
    """Reserve seats on a flight for passengers."""
    logger.info(f"Tool called: reserve_flight(flight_id={flight_id}, passengers={len(passengers)})")
    logger.debug(f"Passengers: {passengers}, Requested seats: {requested_seats}")
    try:
        reservation = get_db_manager().create_reservation(flight_id, passengers, requested_seats)
        logger.debug(f"Reservation result:\n{json.dumps(reservation, indent=2)}")
        return json.dumps(reservation, indent=2)

    except ValueError as e:
        logger.warning(f"Validation error in reserve_flight: {e}")
        return json.dumps({"error": "Invalid reservation parameters"})
    except Exception as e:
        logger.exception(f"Database error in reserve_flight: {e}")
        return json.dumps({"error": "An internal database error occurred"})


@tool
def confirm_booking(
    booking_number: str,
) -> str:
    """Confirm and finalize a flight booking."""
    logger.info(f"Tool called: confirm_booking(booking_number={booking_number})")
    try:
        confirmation = get_db_manager().confirm_booking(booking_number)
        logger.debug(f"Confirmation result:\n{json.dumps(confirmation, indent=2)}")
        return json.dumps(confirmation, indent=2)

    except ValueError as e:
        logger.warning(f"Validation error in confirm_booking: {e}")
        return json.dumps({"error": "Invalid booking confirmation parameters"})
    except Exception as e:
        logger.exception(f"Database error in confirm_booking: {e}")
        return json.dumps({"error": "An internal database error occurred"})


@tool
def process_payment(
    booking_number: str,
    payment_method: str,
    amount: float | None = None,
) -> str:
    """Process payment for a booking (simulated)."""
    logger.info(
        f"Tool called: process_payment(booking_number={booking_number}, payment_method={payment_method})"
    )
    logger.debug(f"Payment amount: {amount}")
    try:
        payment_result = get_db_manager().process_payment(booking_number, payment_method, amount)
        logger.debug(f"Payment result:\n{json.dumps(payment_result, indent=2)}")
        return json.dumps(payment_result, indent=2)

    except ValueError as e:
        logger.warning(f"Validation error in process_payment: {e}")
        return json.dumps({"error": "Invalid payment parameters"})
    except Exception as e:
        logger.exception(f"Database error in process_payment: {e}")
        return json.dumps({"error": "An internal database error occurred"})


@tool
def manage_reservation(
    booking_number: str,
    action: str,
    reason: str | None = None,
) -> str:
    """Update, view, or cancel existing reservations."""
    logger.info(
        f"Tool called: manage_reservation(booking_number={booking_number}, action={action})"
    )
    logger.debug(f"Reason: {reason}")
    try:
        db_manager = get_db_manager()
        if action == "view":
            booking_details = db_manager.get_booking_details(booking_number)
            logger.debug(f"Booking details:\n{json.dumps(booking_details, indent=2)}")
            return json.dumps(booking_details, indent=2)

        elif action == "cancel":
            if not reason:
                error_msg = "Cancellation reason is required"
                logger.warning(error_msg)
                return json.dumps({"error": error_msg})

            cancellation_result = db_manager.cancel_booking(booking_number, reason)
            logger.debug(f"Cancellation result:\n{json.dumps(cancellation_result, indent=2)}")
            return json.dumps(cancellation_result, indent=2)

        else:
            error_msg = f"Unknown action: {action}. Supported actions: view, cancel"
            logger.warning(error_msg)
            return json.dumps({"error": error_msg})

    except ValueError as e:
        logger.warning(f"Validation error in manage_reservation: {e}")
        return json.dumps({"error": "Invalid reservation parameters"})
    except Exception as e:
        logger.exception(f"Database error in manage_reservation: {e}")
        return json.dumps({"error": "An internal database error occurred"})


# TODO: Create tool that's able to dynamically search agents from MCP Registry
# example:
# @tool
# def delegate_to_agent(agent_capability: str, action: str, params: Dict) -> str:

FLIGHT_BOOKING_TOOLS = [
    check_availability,
    reserve_flight,
    confirm_booking,
    process_payment,
    manage_reservation,
]

# Tools that never change state. Every other tool, and any tool not listed in
# FLIGHT_BOOKING_TOOLS, is treated as mutating by the execution-boundary guard.
_READ_ONLY_TOOLS: frozenset[str] = frozenset({"check_availability"})


def is_read_only_tool_call(
    tool_name: str,
    tool_input: dict[str, Any],
) -> bool:
    """Classify a model-emitted tool call as read-only (True) or mutating (False).

    ``manage_reservation`` is read-only only for ``action == "view"``; its cancel
    action (and any unknown action) is mutating.

    Args:
        tool_name: Name of the tool the model called.
        tool_input: Arguments the model supplied.

    Returns:
        True only when the call provably cannot change state.
    """
    if tool_name in _READ_ONLY_TOOLS:
        return True
    if tool_name == "manage_reservation":
        return tool_input.get("action") == "view"
    return False
