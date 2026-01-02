const webpack = require('@nativescript/webpack');

module.exports = (env) => {
  webpack.init(env);

  // INVALID: This entry point will cause runtime crash
  webpack.chainWebpack((config) => {
    config.entry('bundle').clear().add('./');
  });

  return webpack.resolveConfig();
};
