import { defineConfig } from "vite";

// Build the web client to web/dist with content-hashed assets. `base:
// "./"` keeps asset URLs relative so the same bundle works embedded in
// the binary (served at /) or from an S3/CDN sub-path. (DESIGN §13.3)
export default defineConfig({
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
  },
});
