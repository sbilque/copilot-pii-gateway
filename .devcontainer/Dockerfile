FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

USER root

# Le dépôt APT Yarn de l'image de base bloque apt-get update.
# Inutile pour ce lab Python : le retirer avant l'installation des features.
RUN rm -f /etc/apt/sources.list.d/yarn.list
