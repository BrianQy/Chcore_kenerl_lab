#!/bin/bash
docker run -it --rm -u $(id -u ${USER}):$(id -g ${USER}) -v $(pwd):/chos -w /chos ipads/chcore_builder:v1.0 /bin/bash -c "ls;cd tests/mm/buddy/;rm -rf test_buddy;cmake ./;make;ls;pwd;./test_buddy"
