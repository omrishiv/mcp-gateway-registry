import { extractErrorDetail } from '../apiError';

describe('extractErrorDetail', () => {
  it('returns a plain string detail', () => {
    const err = { response: { data: { detail: 'nope' } } };
    expect(extractErrorDetail(err, 'fallback')).toBe('nope');
  });

  it('joins validation-array detail msgs', () => {
    const err = {
      response: { data: { detail: [{ msg: 'bad a' }, { msg: 'bad b' }] } },
    };
    expect(extractErrorDetail(err, 'fallback')).toBe('bad a, bad b');
  });

  it('falls back when detail is absent', () => {
    expect(extractErrorDetail(new Error('x'), 'fallback')).toBe('fallback');
  });

  it('falls back when the validation array has no usable msgs', () => {
    const err = { response: { data: { detail: [{}, {}] } } };
    expect(extractErrorDetail(err, 'fallback')).toBe('fallback');
  });
});
