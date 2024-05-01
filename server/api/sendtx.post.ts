export default defineEventHandler(async (event) => {
  if (event.node.req.url) {
    let body = await readBody(event);
    if (body instanceof Uint8Array) {
      body = JSON.parse(new TextDecoder().decode(body));
    }
    try {
      const request = {
        body: JSON.stringify(body),
        method: 'POST',
        headers: {
          'content-type': 'application/json;charset=UTF-8',
        },
      };
      const response = await fetch(event.node.req.url.replace('/api', 'https://testnet-openapi.fireacademy.io/v1'), request);
      return await response.json();
    } catch (e: any) {
      console.log(e);
      throw createError({
        statusCode: 400,
        statusMessage: e.message,
      });
    }
  }
});
