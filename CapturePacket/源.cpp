#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <time.h>
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    /*
    * 调用 GetSystemDirectory 函数获取系统目录路径，并将其存储在 npcap_dir 中。
    * 函数的第二个参数 480 表示 npcap_dir 变量的最大大小为 480。
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * 使用 _tcscat_s 函数将 \Npcap 字符串追加到 npcap_dir 变量末尾，形成完整的 Npcap 安装目录路径。
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * 调用 SetDllDirectory 函数设置 DLL 的搜索路径为 npcap_dir，使得程序可以找到并加载该目录下的 DLL 文件。如果函数返回值为 0，则说明设置失败，打印错误信息并返回 FALSE。
    */
    return TRUE;
}

#pragma pack(1)

//6字节的MAC地址
typedef struct MACAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}MACAddress;

//4字节的IP地址
typedef struct IPAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}IPAddress;

//FrameHeader
typedef struct FrameHeader {
    MACAddress destination_mac_address;
    MACAddress source_mac_address;
    WORD type;
}FrameHeader;

//IPHeader
typedef struct IPHeader {
    u_char  ver_ihl;//版本（4bits）和包头长度（4bits）
    u_char  tos;//服务类型
    u_short tlen;//总长度
    u_short identification;//标识
    u_short flags_fo;//标志和片偏移
    u_char  ttl;//生存周期
    u_char  proto;//协议
    u_short crc;//头部校验和
    IPAddress  saddr;//源IP地址
    IPAddress  daddr;//目的IP地址
    u_int  op_pad;//选择+填充
}IPHeader;
#pragma pack()

//回调函数的声明
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
    pcap_if_t* alldevs;//用于存储所有的设备
    pcap_if_t* d;//用于遍历所有设备
    int dev_num;//要打开第几个设备
    int i = 0;//循环变量
    pcap_t* adhandle;//打开的网络接口设备
    char errbuf[PCAP_ERRBUF_SIZE];//存储错误信息的buffer
    u_int netmask;//子网掩码
    char packet_filter[] = "ip";//过滤器：只接受ip数据包
    struct bpf_program fcode;

    //加载NPcap相关函数，如果没有加载成功，那么输出错误信息并退出程序。
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap加载错误\n");
        exit(1);
    }
     
    //获取网络设备列表，如果返回-1，说明函数执行失败，输出错误信息并退出程序。
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs_ex执行失败: %s\n", errbuf);
        exit(1);
    }

    int count_dev = 0;
    //输出设备列表，并用count_dev进行计数
    for (d = alldevs; d; d = d->next)
    {
        count_dev++;
        printf("%d. %s", count_dev, d->name);
        if (d->description)//对设备的描述
            printf(" (%s)\n", d->description);
        else
            printf(" (无描述)\n");
    }

    //如果设备列表为空，则输出提示信息，主函数返回-1
    if (count_dev == 0)
    {
        printf("\n没有找到设备\n");
        return -1;
    }

    //输入设备的标号
    printf("输入设备的标号:");
    scanf_s("%d", &dev_num);

    //检查dev_num的合法性
    if (dev_num < 1 || dev_num > count_dev)
    {
        printf("\n输入的标号超出范围！\n");
        pcap_freealldevs(alldevs);//释放所有的设备
        return -1;
    }

    //将d设置为选择的设备
    for (d = alldevs, i = 0; i < dev_num - 1; d = d->next, i++);

    //调用pcap_open,打开选定的网络接口设备，返回一个指向pcap_t类型的句柄adhandle
    if ((adhandle = pcap_open(
        d->name, //接口设备的名字
        65536, // 表示要捕获的数据包的最大大小，65536 表示捕获所有的数据
        PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
        1000, // 超时时间
        NULL, // 远程认证
        errbuf // error buffer
        )) == NULL)
    {
        fprintf(stderr,"\n打开选定的网络接口设备失败\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //获取网络接口设备的子网掩码
    if (d->addresses != NULL)
    {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }   
    else
    {
        //假设设备在一个C类网络中
        netmask = 0xffffff;
    }


    //编译网络数据包过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n过滤器编译失败\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //设置已编译的网络数据包过滤器。
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n过滤器设置错误\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n正在捕获数据包（ %s ）...\n", d->description);
    pcap_freealldevs(alldevs);

    //捕获数据包
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}
//回调函数的实现
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    FrameHeader* fh;
    IPHeader* ih;

    //从pkt_data中获取fh
    fh = (FrameHeader*)pkt_data;
    
    //从pkt_data中获取ih
    ih = (IPHeader*)(pkt_data + 14); 

    //输出信息
    printf("源IP地址：%d.%d.%d.%d ->目的IP地址： %d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,

        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4
        );
    printf("源MAC地址：%d.%d.%d.%d.%d.%d ->目的MAC地址：%d.%d.%d.%d.%d.%d\n",
        fh->source_mac_address.byte1,
        fh->source_mac_address.byte2,
        fh->source_mac_address.byte3,
        fh->source_mac_address.byte4,
        fh->source_mac_address.byte5,
        fh->source_mac_address.byte6,

        fh->destination_mac_address.byte1,
        fh->destination_mac_address.byte2,
        fh->destination_mac_address.byte3,
        fh->destination_mac_address.byte4,
        fh->destination_mac_address.byte5,
        fh->destination_mac_address.byte6
    );
    printf("\t数据帧类型：%d\n", fh->type);
    printf("\t服务类型：%d\n", ih->tos);
    printf("\t总长度：%hu\n", ih->tlen);
}