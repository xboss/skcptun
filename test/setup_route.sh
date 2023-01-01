#/bin/sh
cmd=$1
ip_list_file=$2
target_gw=$3
def_gw=$3
tuntap_dev=$4

usage() {
    echo "Usage: $0 <cmd> <param>"
}

if [[ -z "${cmd}" ]]; then
    echo "命令为空"
    usage
    exit 1
fi

if [[ -z "${ip_list_file}" ]]; then
    echo "ip列表文件为空"
    usage
    exit 1
fi


if [ ! -f $ip_list_file ];then
  echo "ip列表文件不存在"
  usage
  exit 1
fi

if [[ "${cmd}" == "add" ]]; then
    if [ ! $target_gw ];then
        echo "路由地址为空"
        usage
        echo "$0 add ip_list_file target_gw tuntap_dev"
        exit 1
    fi

    if [[ -z "${tuntap_dev}" ]]; then
        echo "虚拟网卡为空"
        usage
        echo "$0 add target_gw ip_list_file tuntap_dev"
        exit 1
    fi

    for ip_addr in `cat $ip_list_file | awk '{print $1}'`
    do
       echo "ip route add $ip_addr via $target_gw"
       ip route add $ip_addr via $target_gw
    done

    # change default route
    ip route del default
    ip route add default dev ${tuntap_dev}

   exit 0
fi



if [[ "${cmd}" == "del" ]]; then
    if [ ! $def_gw ];then
        echo "默认路由IP为空"
        usage
        echo "$0 del ip_list_file default_dev"
        exit 1
    fi

    # rollback default route
    ip route del default
    ip route add default via ${def_gw}

    cat $ip_list_file | awk '{print "ip route del " $1 }' | sh
    exit 0
fi

usage