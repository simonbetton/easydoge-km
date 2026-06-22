import { readFile } from 'node:fs/promises';

async function main() {
  const [leftPath, rightPath] = process.argv.slice(2);
  if (!leftPath || !rightPath) {
    throw new Error('usage: node compare.mjs <left.json> <right.json>');
  }

  const left = JSON.parse(await readFile(leftPath, 'utf8'));
  const right = JSON.parse(await readFile(rightPath, 'utf8'));
  const leftCanonical = stableStringify(left);
  const rightCanonical = stableStringify(right);

  if (leftCanonical === rightCanonical) {
    console.log('Cross-check outputs match.');
    return;
  }

  const mismatch = firstMismatch(left, right);
  console.error('Cross-check outputs differ.');
  console.error(`First mismatch: ${mismatch.path}`);
  console.error(`Left:  ${stableStringify(mismatch.left)}`);
  console.error(`Right: ${stableStringify(mismatch.right)}`);
  process.exitCode = 1;
}

function stableStringify(value) {
  return JSON.stringify(sortValue(value), null, 2);
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortValue(value[key])]),
    );
  }
  return value;
}

function firstMismatch(left, right, path = '$') {
  if (Object.is(left, right)) {
    return null;
  }

  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) {
      return { path, left, right };
    }
    if (left.length !== right.length) {
      return { path: `${path}.length`, left: left.length, right: right.length };
    }
    for (let index = 0; index < left.length; index += 1) {
      const mismatch = firstMismatch(left[index], right[index], `${path}[${index}]`);
      if (mismatch) {
        return mismatch;
      }
    }
    return null;
  }

  if (isObject(left) || isObject(right)) {
    if (!isObject(left) || !isObject(right)) {
      return { path, left, right };
    }
    const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
    for (const key of keys) {
      if (!(key in left) || !(key in right)) {
        return { path: `${path}.${key}`, left: left[key], right: right[key] };
      }
      const mismatch = firstMismatch(left[key], right[key], `${path}.${key}`);
      if (mismatch) {
        return mismatch;
      }
    }
    return null;
  }

  return { path, left, right };
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
