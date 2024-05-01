export default defineEventHandler(async (event) => {
  if (event.node.req.url) {
    return await $fetch(event.node.req.url.replace('/api', 'https://testnet-openapi.fireacademy.io/v1'));
  }
});
