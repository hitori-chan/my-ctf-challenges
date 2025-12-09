FROM php:8-apache

RUN apt-get update
RUN apt-get install -y gcc
RUN docker-php-ext-install mysqli

COPY ./flag.txt ./readflag.c /
RUN chmod 640 /flag.txt

RUN gcc /readflag.c -o /readflag -O2 -s
RUN chmod 4755 /readflag

COPY ./src/ /var/www/html

RUN chown root:root /var/www/html
RUN chmod 1777 /var/www/html
RUN chmod 1777 /var/www/html/notes

CMD apache2-foreground
