docker run -d \
  -it \
  --mount type=bind,source=/var/www_esinko/live,target=/usr/src/app/live \
  esinko/site