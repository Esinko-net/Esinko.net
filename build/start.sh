docker run -d \
  -it \
  --mount type=bind,source=REPLACE THIS WITH THE TARGET DIRECTORY,target=/usr/src/app/live \
  esinko/site