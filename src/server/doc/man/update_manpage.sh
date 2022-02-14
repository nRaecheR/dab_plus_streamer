#!/bin/sh

help2man \
  --name "dab-plus-streamer command line interface" \
  --no-info \
  --no-discard-stderr \
  --help-option='-h' \
  --version-option="-v" \
  --output dab-plus-streamer.1 \
  dab-plus-streamer
