"use strict";
/* global module */

const MESSAGE =
  "Local image dimension parsing is disabled; use the bounded Cloudflare image transform path.";

const types = Object.freeze([]);

function disableTypes() {}

function imageSize() {
  throw new TypeError(MESSAGE);
}

async function imageSizeFromFile() {
  throw new TypeError(MESSAGE);
}

module.exports = { disableTypes, imageSize, imageSizeFromFile, types };
