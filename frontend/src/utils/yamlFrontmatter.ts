/**
 * Parse YAML frontmatter from a markdown document.
 *
 * Used by the SKILL.md viewers (SkillCard and SemanticSearchResults' skill
 * content modal), which previously each carried an identical copy. This is a
 * deliberately minimal `key: value` parser — it does not handle nested YAML,
 * lists, or multi-line values, matching the original inline behavior.
 *
 * @returns the parsed frontmatter (or null if absent) and the remaining body.
 */
export function parseYamlFrontmatter(content: string): {
  frontmatter: Record<string, string> | null;
  body: string;
} {
  const frontmatterRegex = /^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/;
  const match = content.match(frontmatterRegex);

  if (!match) {
    return { frontmatter: null, body: content };
  }

  const yamlContent = match[1];
  const body = match[2];
  const frontmatter: Record<string, string> = {};
  for (const line of yamlContent.split('\n')) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.substring(0, colonIndex).trim();
      const value = line.substring(colonIndex + 1).trim();
      if (key && value) {
        frontmatter[key] = value;
      }
    }
  }

  return {
    frontmatter: Object.keys(frontmatter).length > 0 ? frontmatter : null,
    body,
  };
}
