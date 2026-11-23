// Minified bundle exercising the source-map pipeline inputs for js-analysis (#193):
// a source map reference, a router path table, webpack chunk URLs, and a high-entropy
// token assigned to an innocuous identifier.
var routes = [
  { path: "/account/profile", component: function () { return import("./chunks/Profile"); } },
  { path: "/admin/panel", component: function () { return import("./chunks/Admin"); } }
];
window.__CHUNKS__ = {
  admin: "/static/js/admin.chunk.js",
  checkout: "/static/js/checkout.chunk.js"
};
var innocuous = Object.freeze({ nonce: "x9Kd3mQ7vR2zT8wL5nB6fG1hJ3dE4uS0pY6aN8cI2o" });
//# sourceMappingURL=app.js.map