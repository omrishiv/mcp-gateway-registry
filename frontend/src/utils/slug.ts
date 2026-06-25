/**
 * Slug / path helpers shared by the registration forms.
 *
 * The "name -> path" auto-generation was duplicated in RegisterPage
 * (generatePath) and VirtualServerForm (_generatePathFromName); they differ
 * only in the leading path segment.
 */

/** Lowercase, hyphenate, and trim leading/trailing hyphens. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Build a registry path from a display name: `<prefix>/<slug>`. Returns '' for
 * an empty name so callers can leave the path blank. `prefix` is the leading
 * segment without a trailing slash (e.g. '' -> "/slug", 'virtual' -> "/virtual/slug").
 */
export function pathFromName(name: string, prefix = ''): string {
  if (!name) return '';
  const slug = slugify(name);
  return prefix ? `/${prefix}/${slug}` : `/${slug}`;
}
