import { isSafeUrl } from '../safeUrl';

// Property: whenever isSafeUrl accepts a string, the WHATWG URL parser (what
// the browser uses for an href) resolves it to http:, https: or mailto:, or
// refuses to parse it. The guard and the parser must never disagree in the
// unsafe direction.
//
// The inputs are every string obtained by inserting up to MAX_INSERTIONS
// characters from INSERTABLE at every position of each template. INSERTABLE
// holds the characters the URL parser strips or treats specially (C0 controls,
// spaces, the BOM and NBSP, and the scheme and path delimiters), so the
// enumeration covers each way of hiding or splitting a scheme with them.

const INSERTABLE: readonly string[] = [
  '\t',
  '\n',
  '\r',
  '\0',
  ' ',
  '\u00a0',
  '\ufeff',
  ':',
  '/',
  '\\',
];

const MAX_INSERTIONS = 2;

const BASE_URL = 'https://base.example/';

const ALLOWED_PROTOCOLS: Readonly<Record<string, true>> = {
  'http:': true,
  'https:': true,
  'mailto:': true,
};

// Each template with whether the guard accepts it unmodified, so the run
// cannot pass vacuously by rejecting every variant of a safe template.
const TEMPLATES: ReadonlyArray<[string, boolean]> = [
  ['javascript:alert(1)', false],
  ['JaVaScRiPt:x', false],
  ['data:text/html,x', false],
  ['vbscript:x', false],
  ['http://a', true],
  ['https://a', true],
  ['mailto:a@b', true],
];

interface Violation {
  input: string;
  protocol: string;
}

/** Every string formed by inserting one INSERTABLE character into `value`. */
const insertOne = (value: string): string[] => {
  const variants: string[] = [];
  for (let position = 0; position <= value.length; position += 1) {
    for (const char of INSERTABLE) {
      variants.push(value.slice(0, position) + char + value.slice(position));
    }
  }
  return variants;
};

/** `template` plus every string reachable by up to MAX_INSERTIONS insertions. */
const enumerateVariants = (template: string): Set<string> => {
  const seen = new Set<string>([template]);
  let frontier: string[] = [template];
  for (let depth = 0; depth < MAX_INSERTIONS; depth += 1) {
    const next: string[] = [];
    for (const value of frontier) {
      for (const variant of insertOne(value)) {
        if (!seen.has(variant)) {
          seen.add(variant);
          next.push(variant);
        }
      }
    }
    frontier = next;
  }
  return seen;
};

/** The protocol the URL parser resolves `value` to, or null if it throws. */
const resolvedProtocol = (value: string): string | null => {
  try {
    return new URL(value, BASE_URL).protocol;
  } catch {
    return null;
  }
};

describe('isSafeUrl against the WHATWG URL parser (exhaustive insertions)', () => {
  it.each(TEMPLATES)(
    'every accepted variant of %j resolves to http, https or mailto',
    (template, acceptedUnmodified) => {
      expect(isSafeUrl(template)).toBe(acceptedUnmodified);

      const violations: Violation[] = [];
      for (const candidate of enumerateVariants(template)) {
        if (!isSafeUrl(candidate)) {
          continue;
        }
        const protocol = resolvedProtocol(candidate);
        if (protocol !== null && ALLOWED_PROTOCOLS[protocol] !== true) {
          violations.push({ input: candidate, protocol });
        }
      }
      expect(violations).toEqual([]);
    },
  );
});
