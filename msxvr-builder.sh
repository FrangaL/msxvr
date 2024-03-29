#!/bin/bash -e

: <<'DISCLAIMER'
This script is licensed under the terms of the MIT license.
Unless otherwise noted, code reproduced herein
was written for this script.
- Fco José Rodríguez Martos - frangal_at_gmail.com -
DISCLAIMER

# Debugging script
[[ "$*" == *--debug* ]] && exec > >(tee -a -i "${0%.*}.log") 2>&1 && set -x

# Configuración básica
OS=${OS:-"raspios"}
RELEASE=${RELEASE:-"buster"}
ROOT_PASSWORD=${ROOT_PASSWORD:-"raspberry"}
HOST_NAME=${HOST_NAME:-"msxvr"}
COMPRESS=${COMPRESS:-"xz"}
LOCALES=${LOCALES:-"es_ES.UTF-8"}
TIMEZONE=${TIMEZONE:-"Europe/Madrid"}
ARCHITECTURE=${ARCHITECTURE:-"armhf"}
VARIANT=${VARIANT:-"lite"}
FSTYPE=${FSTYPE:-"ext4"}
BOOT_MB=${BOOT_MB:-"136"}
FREE_SPACE=${FREE_SPACE:-"200"}
MACHINE=$(dbus-uuidgen)

# Mirrors de descarga
DEB_MIRROR="http://deb.debian.org/debian"
PIOS_MIRROR="http://raspbian.raspberrypi.org/raspbian/"
RASP_MIRROR="http://archive.raspbian.org/raspbian/"
# Key server
KEY_SRV=${KEY_SRV:-"keyserver.ubuntu.com"}
# raspberrypi-archive-keyring
PIOS_KEY="82B129927FA3303E"
# raspbian-archive-keyring
RASP_KEY="9165938D90FDDD2E"

# Entorno de trabajo
IMGNAME="${OS}-${RELEASE}-${VARIANT}-${ARCHITECTURE}.img"
CURRENT_DIR="$(pwd)"
BASEDIR="${CURRENT_DIR}/${OS}_${RELEASE}_${VARIANT}_${ARCHITECTURE}"
R="${BASEDIR}/build"

# Detectar privilegios
[ $EUID -ne 0 ] && echo "Usar: sudo $0" 1>&2 && exit 1

# Detecta antigua instalación
if [ -e "$BASEDIR" ]; then
  echo "El directorio $BASEDIR existe, no se continuara"
  exit 1
elif [[ $BASEDIR =~ [[:space:]] ]]; then
  echo "El directorio "\"$BASEDIR"\" contiene espacios en blanco. No soportado."
  exit 1
fi

mkdir -p "$R"

# Show progress
status() {
  status_i=$((status_i+1))
  echo -e "\e[32m ✅ ${status_i}/${status_t}:\033[0m $1"
}
status_i=0
status_t=$(($(grep '.*status ' $0 | wc -l) -1))
# Override tee command
tee() { [ "$(test $1)" != "${1%/*}" ] && mkdir -p ${1%/*} && echo "$1"; command tee "$1"; }
# Función para instalar dependencias del script
installdeps() {
  APT_UPDATE=${APT_UPDATE:-"0"}
  [[ $APT_UPDATE == "0" ]] && apt-get update; APT_UPDATE="1"
  apt-get -q -y install --no-install-recommends -o APT::Install-Suggests=0 \
      -o dpkg::options::=--force-confnew -o Acquire::Retries=3 $DEPS
}

status "Instalar dependencias ..."
DEPS="binfmt-support dosfstools qemu-user-static rsync wget lsof git parted dirmngr e2fsprogs \
systemd-container debootstrap xz-utils kmod udev dbus gnupg gnupg-utils debian-archive-keyring lftp"
installdeps

# Checkear versión mínima debootstrap
if dpkg --compare-versions "$(dpkg-query -f '${Version}' -W debootstrap)" lt "1.0.105"; then
  echo "Actualmente su versión de debootstrap no soporta el script" >&2
  echo "Actualice debootstrap, versión mínima 1.0.105" >&2
  exit 1
fi

# Variables según arquitectura
case ${ARCHITECTURE} in
  arm64)
    QEMUARCH="qemu-aarch64"
    QEMUBIN="/usr/bin/qemu-aarch64-static" ;;
  armhf)
    QEMUARCH="qemu-arm"
    QEMUBIN="/usr/bin/qemu-arm-static" ;;
esac

# Detectar modulo binfmt_misc cargado en el kernel
MODBINFMT=$(lsmod | grep binfmt_misc | awk '{print $1}')
BINFMTS=$(awk </proc/sys/fs/binfmt_misc/${QEMUARCH} '{if(NR==1) print $1}')
if [ -z "${MODBINFMT}" ]; then
  modprobe binfmt_misc &>/dev/null
elif [ "${BINFMTS}" == "disabled" ]; then
  update-binfmts --enable $QEMUARCH &>/dev/null
fi

# Check systemd-nspawn versión
NSPAWN_VER=$(systemd-nspawn --version | awk '{if(NR==1) print $2}')
if [[ $NSPAWN_VER -ge 245 ]]; then
  EXTRA_ARGS="--hostname=$HOST_NAME -q -P"
elif [[ $NSPAWN_VER -ge 241 ]]; then
  EXTRA_ARGS="--hostname=$HOST_NAME -q"
else
  EXTRA_ARGS="-q"
fi
# Entorno systemd-nspawn
systemd-nspawn_exec() {
  ENV="RUNLEVEL=1,LANG=C,DEBIAN_FRONTEND=noninteractive,DEBCONF_NOWARNINGS=yes"
  systemd-nspawn --bind $QEMUBIN $EXTRA_ARGS --capability=cap_setfcap -E $ENV -M "$MACHINE" -D "${R}" "$@"
}

# Base debootstrap
COMPONENTS="main contrib non-free"
MINPKGS="ifupdown openresolv net-tools init dbus rsyslog cron wget gnupg libterm-readline-gnu-perl dialog"
EXTRAPKGS="parted locales dosfstools sudo keyboard-configuration console-setup alsa-utils"
FIRMWARES="firmware-misc-nonfree firmware-atheros firmware-realtek firmware-libertas firmware-brcm80211"
WIRELESSPKGS="wpasupplicant crda wireless-tools rfkill wireless-regdb"
BLUETOOTH="bluetooth bluez bluez-tools"
MSXVR="cups cups-client avrdude smbclient poppler-utils ufiformat zip openal-info lhasa rcconf espeak sdcc git"
MSXVR_LIB="libgbm-dev libtheora-dev libgmp-dev libdrm-dev libbluetooth-dev libpcap-dev libcurl4-openssl-dev libmpg123-dev libftp-dev libopenal-dev libopenal1 libasound2-dev libgbm1 libgles2-mesa-dev"

if [[ "${OS}" == "raspios" ]]; then
  BOOT="/boot"
  KERNEL_IMAGE="raspberrypi-kernel raspberrypi-bootloader"
  case ${OS}+${ARCHITECTURE} in
    raspios*arm64)
      MIRROR=$PIOS_MIRROR
      MIRROR_PIOS=${MIRROR/raspbian./archive.}
      KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
      GPG_KEY=$PIOS_KEY
      BOOTSTRAP_URL=$DEB_MIRROR
      ;;
    raspios*armhf)
      MIRROR=$RASP_MIRROR
      KEYRING=/usr/share/keyrings/raspbian-archive-keyring.gpg
      GPG_KEY=$RASP_KEY
      BOOTSTRAP_URL=$RASP_MIRROR
      ;;
  esac
fi

status "Instalardo certificados ..."
if [ ! -f $KEYRING ]; then
  GNUPGHOME="$(mktemp -d)"
  export GNUPGHOME
  gpg --keyring=$KEYRING --no-default-keyring --keyserver-options timeout=10 --keyserver "$KEY_SRV" --receive-keys $GPG_KEY
  rm -rf "${GNUPGHOME}"
fi

status "debootstrap first stage"
sed -i'.bkp' 's/^keyring.*/keyring $KEYRING\ndefault_mirror $BOOTSTRAP_URL/' /usr/share/debootstrap/scripts/sid
debootstrap --foreign --arch="${ARCHITECTURE}" --components="${COMPONENTS// /,}" --variant - \
  --keyring=$KEYRING --exclude="info,install-info" --include="${MINPKGS// /,}" "$RELEASE" "$R" $BOOTSTRAP_URL
mv /usr/share/debootstrap/scripts/sid{.bkp,}

if [[ "${VARIANT}" == "lite" ]]; then
  cat >"$R"/etc/dpkg/dpkg.cfg.d/01_no_doc_locale <<EOF
path-exclude /usr/lib/systemd/catalog/*
path-exclude /usr/share/doc/*
path-include /usr/share/doc/*/copyright
path-exclude /usr/share/man/*
path-exclude /usr/share/groff/*
path-exclude /usr/share/info/*
path-exclude /usr/share/lintian/*
path-exclude /usr/share/linda/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
path-include /usr/share/locale/es*
path-include /usr/share/locale/locale.alias
EOF

  # Raspberry PI no tiene pci ni acpi
  cat >"$R"/etc/dpkg/dpkg.cfg.d/02_no_pci_acpi <<EOF
path-exclude=/lib/udev/hwdb.d/20-pci*
path-exclude=/lib/udev/hwdb.d/20-acpi*
EOF
fi

status "debootstrap second stage"
systemd-nspawn_exec /debootstrap/debootstrap --second-stage

# Definir sources.list
case ${OS}+${ARCHITECTURE} in
  raspios*arm64)
  echo "deb ${MIRROR_PIOS/raspbian/debian} $RELEASE main" >"$R"/etc/apt/sources.list.d/raspi.list ;;
  raspios*armhf)
  MIRROR=${PIOS_MIRROR/raspbian./archive.}
  echo "deb ${MIRROR/raspbian/debian} $RELEASE main" >"$R"/etc/apt/sources.list.d/raspi.list ;;
esac

# Instalar archive-keyring en PiOS
if [ "$OS" = "raspios" ]; then
  [[ "$RELEASE" == "buster" ]] && MSXVR+=" omxplayer"
  systemd-nspawn_exec apt-key adv --keyserver-options timeout=10 --keyserver $KEY_SRV --recv-keys $PIOS_KEY
fi

# Scripts para redimensionar partición root
cat >"$R"/etc/systemd/system/rpi-resizerootfs.service <<EOM
[Unit]
Description=resize root file system
Before=local-fs-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
TimeoutSec=infinity
ExecStart=/usr/sbin/rpi-resizerootfs
ExecStart=/bin/systemctl --no-reload disable %n

[Install]
RequiredBy=local-fs-pre.target
EOM

cat >"$R"/usr/sbin/rpi-resizerootfs <<\EOM
#!/bin/sh
DISKPART="$(findmnt -n -o SOURCE /)"
DISKNAME="/dev/$(lsblk -no pkname "$DISKPART")"
DISKNAMENR="$(blkid -sPART_ENTRY_NUMBER -o value -p $DISKNAME)"
flock ${DISKNAME} sfdisk -f ${DISKNAME} -N $DISKNAMENR <<EOF
,+
EOF

sleep 5
udevadm settle
sleep 5
flock ${DISKNAME} partprobe ${DISKNAME}
mount -o remount,rw ${DISKPART}
resize2fs ${DISKPART}
EOM
chmod -c 755 "$R"/usr/sbin/rpi-resizerootfs

status "Configurar usuarios y grupos"
systemd-nspawn_exec <<_EOF
adduser --gecos pi --disabled-password pi
echo "pi:${ROOT_PASSWORD}" | chpasswd
echo spi i2c gpio | xargs -n 1 groupadd -r
usermod -a -G adm,dialout,sudo,audio,video,plugdev,users,netdev,input,spi,gpio,i2c,sudo pi
_EOF

# Autologin root
systemd-nspawn_exec <<_EOF
systemctl set-default multi-user.target
systemctl enable getty@tty1.service
_EOF
mkdir -p "$R"/etc/systemd/system/getty@tty1.service.d/
cat > "$R"/etc/systemd/system/getty@tty1.service.d/autologin.conf << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --skip-login --noclear --noissue --login-options "-f root" %I $TERM
EOF

# Auto run MSXVR
cat > "$R"/etc/profile.d/msxvr.sh << 'EOF'
if [ "$(id -u)" -eq 0 ]; then
  ./run
fi
EOF

# Disable suspend/resume - speeds up boot massively
echo "RESUME=none" | tee "${R}/etc/initramfs-tools/conf.d/resume"

status "Instalando kernel ..."
systemd-nspawn_exec apt-get update
# shellcheck disable=SC2086
systemd-nspawn_exec apt-get install -y ${KERNEL_IMAGE}
# Configuración firmware
if [ "$OS" = raspios ]; then
  cat <<-EOM >"${R}"${BOOT}/cmdline.txt
net.ifnames=0 dwc_otg.lpm_enable=0 console=serial0,115200 console=tty13 loglevel=3 vt.global_cursor_default=0 root=/dev/mmcblk0p2 rootfstype=ext4 elevator=deadline rootwait quiet logo.nologo
EOM
  cp config.txt "$R"/boot
fi

if [ "$ARCHITECTURE" = "arm64" ]; then
  echo "arm_64bit=1" >>"$R"/"${BOOT}"/config.txt
fi

if [[ "${VARIANT}" == "slim" ]]; then
  INCLUDEPKGS="${EXTRAPKGS} ${WIRELESSPKGS} firmware-brcm80211"
elif [[ "${VARIANT}" == "lite" ]]; then
  INCLUDEPKGS="${EXTRAPKGS} ${WIRELESSPKGS} ${BLUETOOTH} ${FIRMWARES}"
fi

# Añadir dependencias de msxvr a la compilación
if [ -n "$MSXVR" ]; then
  INCLUDEPKGS="${MSXVR} ${MSXVR_LIB} ${INCLUDEPKGS}"
fi

status "Instalar paquetes extra"
systemd-nspawn_exec sh -c "DEBIAN_FRONTEND=noninteractive apt-get install -y $INCLUDEPKGS"

if [[ "$RELEASE" == "bullseye" && "$ARCHITECTURE" == "armhf" ]]; then
  wget -nv https://archive.raspberrypi.org/debian/pool/main/o/omxplayer/omxplayer_20190723+gitf543a0d-1+bullseye_armhf.deb
  cp omxplayer_20190723+gitf543a0d-1+bullseye_armhf.deb "$R"/omxplayer_20190723+gitf543a0d-1+bullseye_armhf.deb
  systemd-nspawn_exec apt-get install -y libavcodec58 libavformat58 libavutil56 libswresample3
  systemd-nspawn_exec dpkg -i /omxplayer_20190723+gitf543a0d-1+bullseye_armhf.deb
  systemd-nspawn_exec apt-get install -f -y
  rm -f "$R"/omxplayer_20190723+gitf543a0d-1+bullseye_armhf.deb
fi
wget -nv https://yt-dl.org/downloads/latest/youtube-dl -O "$R"/usr/local/bin/youtube-dl
chmod a+rx "$R"/usr/local/bin/youtube-dl

status "Instalar msxvr tarball"
wget -nv http://msxvr.es/resources/msxvr_root.zip
unzip -q msxvr_root.zip -d "$R"/root
chmod +x "$R"/root/{msxvr_pi3,run}
mkdir -p "$R"/mnt/{usb,fdd}_{1..8}
status "Keyboard config"
wget -nv http://msxvr.es/resources/msxvr_keyboards.zip
unzip -o -q msxvr_keyboards.zip -d "$R"/usr/share/X11/xkb/symbols/
systemd-nspawn_exec dpkg-reconfigure xkb-data
cat >"$R"/etc/dpkg/dpkg.cfg.d/02_keyboards <<EOF
path-exclude /usr/share/X11/xkb/symbols/*
EOF
cat > "$R"/etc/default/keyboard << EOF
XKBMODEL="pc105"
XKBLAYOUT=" + string(_iso) + "
XKBVARIANT=""
XKBOPTIONS=""

BACKSPACE="guess"
EOF
systemd-nspawn_exec setupcon

status "Activar servicio redimendionado partición root"
systemd-nspawn_exec systemctl enable rpi-resizerootfs.service

# Añadir nombre de host
echo "$HOST_NAME" >"$R"/etc/hostname

status "Definir zona horaria"
systemd-nspawn_exec ln -nfs /usr/share/zoneinfo/"$TIMEZONE" /etc/localtime
systemd-nspawn_exec dpkg-reconfigure -fnoninteractive tzdata

# Sin contraseña sudo en el usuario pi
echo "pi ALL=(ALL) NOPASSWD:ALL" >>"$R"/etc/sudoers

status "Configurar locales"
sed -i "s/^# *\($LOCALES\)/\1/" "$R"/etc/locale.gen
systemd-nspawn_exec locale-gen
echo "LANG=$LOCALES" >"$R"/etc/locale.conf
cat <<'EOM' >"$R"/etc/profile.d/default-lang.sh
if [ -z "$LANG" ]; then
    source /etc/locale.conf
    export LANG
fi
EOM

# This needs to be done or wireless doesnt work correctly on the RPi 3B+
sed -i -e 's/REGDOM.*/REGDOMAIN=00/g' "$R"/etc/default/crda

# Instalar f2fs-tools y modificar cmdline.txt
if [ "$FSTYPE" = "f2fs" ]; then
  DEPS="f2fs-tools" installdeps
  systemd-nspawn_exec apt-get install -y f2fs-tools
  sed -i 's/resize2fs/resize.f2fs/g' "$R"/usr/sbin/rpi-resizerootfs
  FSOPTS="rw,acl,active_logs=6,background_gc=on,user_xattr"
elif [ "$FSTYPE" = "ext4" ]; then
  FSOPTS="defaults,noatime"
fi

# Definiendo puntos de montaje
cat >"$R"/etc/fstab <<EOM
proc            /proc           proc    defaults          0       0
/dev/mmcblk0p2  /               $FSTYPE    $FSOPTS  0       1
#/dev/mmcblk0p1  $BOOT  vfat    defaults          0       2
EOM

# Crear archivo hosts
cat >"$R"/etc/hosts <<EOM
127.0.1.1       ${HOST_NAME}
127.0.0.1       localhost
::1             localhostnet.ifnames=0 ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOM

# Preparar configuración de red
cat <<EOF >"$R"/etc/network/interfaces
source-directory /etc/network/interfaces.d

auto lo
iface lo inet loopback

# allow-hotplug wlan0
# iface wlan0 inet dhcp
# wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf

allow-hotplug eth0
iface eth0 inet dhcp
EOF

status "Deshabilitar servicios innecesarios"
echo | sed -e '/^#/d ; /^ *$/d' | systemd-nspawn_exec <<\EOF
# Servicio cron
systemctl disable cron.service
# Servicios apt updates
systemctl disable apt-daily.timer
systemctl disable apt-daily-upgrade.timer
# Servicio man-db
systemctl disable man-db.timer
# Servicio mount fs remoto
systemctl disable remote-fs.target
# Servicios de configuración de teclado
systemctl disable console-setup.service
systemctl disable keyboard-setup.service
EOF

# Fix startup time from 5 minutes to 10 secs on raise interface
echo -e "[Service]\nTimeoutStartSec=10sec" | tee /usr/lib/systemd/system/networking.service.d/override.conf

# Raspberry PI userland tools & raspi-config
if [[ "$OS" == "raspios" && "$VARIANT" == "lite" ]]; then
  systemd-nspawn_exec apt-get install -y libraspberrypi-bin raspi-config
fi

status "Limpiar sistema"
systemd-nspawn_exec apt-get -y remove --purge tasksel tasksel-data
find "$R"/usr/share/doc -empty -print0 | xargs -0 rmdir
if [[ "$VARIANT" == "slim" ]]; then
  find "$R"/usr/share/doc -depth -type f ! -name copyright -print0 | xargs -0 rm
  rm -rf "$R"/usr/share/man/* "$R"/usr/share/info/*
  rm -rf "$R"/usr/share/lintian/*
fi
find "$R"/var/log -depth -type f -print0 | xargs -0 truncate -s 0
rm -f "$R"/usr/bin/qemu*
rm -rf "$R"/etc/dpkg/dpkg.cfg.d/01_no_doc_locale
rm -rf "$R"/etc/apt/apt.conf.d/99_norecommends
rm -rf "$R"/run/* "$R"/etc/*- "$R"/tmp/*
rm -rf "$R"/var/lib/apt/lists/*
rm -rf "$R"/var/cache/apt/archives/*
rm -rf "$R"/var/cache/apt/*.bin
rm -rf "$R"/var/cache/debconf/*-old
rm -rf "$R"/var/lib/dpkg/*-old
rm -rf "$R"/etc/ssh/ssh_host_*
rm -rf "$R"/root/.bash_history
rm -f *.zip

# Crear manifiesto
if [[ "$MANIFEST" == "true" ]]; then
  systemd-nspawn_exec sh -c "dpkg-query -f '\${Package} \${Version}\n' -W > /${IMGNAME}.manifest"
  cp $R/$IMGNAME.manifest $IMGNAME.manifest
  rm -f $R/$IMGNAME.manifest
fi
echo "nameserver $DNS" >"$R"/etc/resolv.conf

status "Calcule el espacio para crear la imagen"
ROOTSIZE=$(du -s -B1 "$R" --exclude="${R}"/boot | cut -f1)
ROOTSIZE=$((ROOTSIZE * 5 * 1024 / 5 / 1000 / 1024))
RAW_SIZE=$(($((FREE_SPACE * 1024)) + ROOTSIZE + $((BOOT_MB * 1024)) + 4096))

status "Crea el disco y particionar"
fallocate -l "$(echo ${RAW_SIZE}Ki | numfmt --from=iec-i --to=si)" "${IMGNAME}"
parted -s "${IMGNAME}" mklabel msdos
parted -s "${IMGNAME}" mkpart primary fat32 1MiB $((BOOT_MB + 1))MiB
parted -s -a minimal "${IMGNAME}" mkpart primary $((BOOT_MB + 1))MiB 100%

# Establecer las variables de partición
LOOPDEVICE=$(losetup --show -fP "${IMGNAME}")
BOOT_LOOP="${LOOPDEVICE}p1"
ROOT_LOOP="${LOOPDEVICE}p2"

status "Formatear particiones"
mkfs.vfat -n BOOT -F 32 -v "$BOOT_LOOP"
if [[ $FSTYPE == f2fs ]]; then
  mkfs.f2fs -f -l ROOTFS "$ROOT_LOOP"
elif [[ $FSTYPE == ext4 ]]; then
  FEATURES="-O ^64bit,^metadata_csum -E stride=2,stripe-width=1024 -b 4096"
  # shellcheck disable=SC2086
  mkfs $FEATURES -t "$FSTYPE" -L ROOTFS "$ROOT_LOOP"
fi

status "Crear los directorios para las particiones y montarlas"
MOUNTDIR="$BUILDDIR/mount"
mkdir -v -p "$MOUNTDIR"
mount -v "$ROOT_LOOP" "$MOUNTDIR"
mkdir -v -p "$MOUNTDIR/$BOOT"
mount -v "$BOOT_LOOP" "$MOUNTDIR/$BOOT"

status "Rsyncing rootfs en archivo de imagen"
rsync -aHAXx --exclude boot "${R}/" "${MOUNTDIR}/"
rsync -rtx "${R}/boot" "${MOUNTDIR}/"

status "Desmontar sistema de archivos y eliminar compilación"
umount -v "$MOUNTDIR/$BOOT"
umount -v "$MOUNTDIR"
rm -rf "$BASEDIR"

status "Chequear particiones"
dosfsck -w -r -a -t "$BOOT_LOOP"
if [[ "$FSTYPE" == "f2fs" ]]; then
  fsck.f2fs -y -f "$ROOT_LOOP"
elif [[ "$FSTYPE" == "ext4" ]]; then
  e2fsck -y -f "$ROOT_LOOP"
fi

# Eliminar dispositivos loop
losetup -d "${LOOPDEVICE}"

status "Comprimiendo imagen ..."
if [[ "$COMPRESS" == "gzip" ]]; then
  gzip "${IMGNAME}"
  chmod 664 "${IMGNAME}.gz"
elif [[ "$COMPRESS" == "xz" ]]; then
  xz -T "$(nproc)" "${IMGNAME}"
  chmod 664 "${IMGNAME}.xz"
else
  chmod 664 "${IMGNAME}"
fi
