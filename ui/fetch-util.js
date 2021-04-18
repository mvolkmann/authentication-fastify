const URL_PREFIX = 'https://api.nodeauth.dev/';

async function deleteResource(path, body) {
  return fetch(URL_PREFIX + path, {
    credentials: 'include', // required to send cookies
    method: 'DELETE'
  });
}

async function getJson(path) {
  const res = await fetch(URL_PREFIX + path, {
    credentials: 'include' // required to send cookies
  });
  return res.ok ? res.json() : res.text();
}

async function postJson(path, body) {
  const res = await fetch(URL_PREFIX + path, {
    method: 'POST',
    body: JSON.stringify(body),
    credentials: 'include', // required to send cookies
    headers: {'Content-Type': 'application/json'}
  });
  const contentType = res.headers.get('Content-Type');
  const isJson = contentType && contentType.startsWith('application/json');
  const result = await (isJson ? res.json() : res.text());
  if (res.ok) return result;
  throw new Error(result);
}
