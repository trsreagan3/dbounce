#!/bin/sh
# postinstall.sh — dbounce post-install notice
# Printed after dpkg/rpm installs the package.
# Does NOT require sudo to run the binary itself.
set -e

echo ""
echo "dbounce installed to /usr/local/bin/dbounce"
echo ""
echo "Verify your install:"
echo "  dbounce --version"
echo ""
echo "Quick start:"
echo "  dbounce run --pg-upstream localhost:5432 --listen 127.0.0.1:15432"
echo ""
echo "Docs: https://github.com/trsreagan3/dbounce/blob/main/README.md"
echo ""
