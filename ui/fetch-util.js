const URL_PREFIX = 'https://api.nodeauth.dev/';

async function deleteResource(path, body) {
  const res = await fetch(URL_PREFIX + path, {
    credentials: 'include', // required to send cookies
    method: 'DELETE'
  });
  const result = await getResult(res);
  if (!res.ok) throw new Error(result);
  return result;
}

async function getJson(path) {
  const res = await fetch(URL_PREFIX + path, {
    credentials: 'include' // required to send cookies
  });
  const result = await getResult(res);
  if (!res.ok) throw new Error(result);
  return result;
}

function getResult(res) {
  const contentType = res.headers.get('Content-Type');
  const isJson = contentType && contentType.startsWith('application/json');
  return isJson ? res.json() : res.text();
}

async function postJson(path, body) {
  const res = await fetch(URL_PREFIX + path, {
    method: 'POST',
    body: JSON.stringify(body),
    credentials: 'include', // required to send cookies
    headers: {'Content-Type': 'application/json'}
  });
  const result = await getResult(res);
  if (!res.ok) throw new Error(result);
  return result;
}
