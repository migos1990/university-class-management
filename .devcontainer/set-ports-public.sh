#!/bin/bash
# Sets all classroom ports to public visibility in Codespaces
# Runs via postAttachCommand each time VS Code attaches to the Codespace
if [ -n "$CODESPACE_NAME" ]; then
  echo "Setting ports 3000-3012 to public visibility..."
  gh codespace ports visibility \
    3000:public 3001:public 3002:public 3003:public \
    3004:public 3005:public 3006:public 3007:public \
    3008:public 3009:public 3010:public 3011:public \
    3012:public \
    -c "$CODESPACE_NAME" 2>/dev/null && echo "Done." || echo "Warning: Could not set port visibility. Check organization policies or set manually in the Ports tab."
else
  echo "Not running in Codespaces -- skipping port visibility setup."
fi
