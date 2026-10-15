const forbidden = new Set(['__proto__', 'prototype', 'constructor']);

export function inspectJson(text, maxBytes) {
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw new Error('File exceeds the preview limit.');
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('Choose a valid JSON document.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('The document root must be an object.');
  const stack = [[value, 0]];
  let count = 0;
  while (stack.length) {
    const [item, depth] = stack.pop();
    if (++count > 20000 || depth > 32) throw new Error('Document is too complex to preview.');
    if (!item || typeof item !== 'object') continue;
    for (const [key, child] of Object.entries(item)) {
      if (forbidden.has(key)) throw new Error('Unsafe document key.');
      stack.push([child, depth + 1]);
    }
  }
  return { value, fields: Object.keys(value), bytes: new TextEncoder().encode(text).byteLength };
}
