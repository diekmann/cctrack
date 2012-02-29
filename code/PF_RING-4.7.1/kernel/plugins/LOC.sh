#!/bin/bash
find ./ -name 'cctrack_*.[c|h]' -o -name 'corny_*.[c|h]' | xargs wc -l
