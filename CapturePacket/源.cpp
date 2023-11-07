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
    * ���� GetSystemDirectory ������ȡϵͳĿ¼·����������洢�� npcap_dir �С�
    * �����ĵڶ������� 480 ��ʾ npcap_dir ����������СΪ 480��
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * ʹ�� _tcscat_s ������ \Npcap �ַ���׷�ӵ� npcap_dir ����ĩβ���γ������� Npcap ��װĿ¼·����
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * ���� SetDllDirectory �������� DLL ������·��Ϊ npcap_dir��ʹ�ó�������ҵ������ظ�Ŀ¼�µ� DLL �ļ��������������ֵΪ 0����˵������ʧ�ܣ���ӡ������Ϣ������ FALSE��
    */
    return TRUE;
}

#pragma pack(1)

//6�ֽڵ�MAC��ַ
typedef struct MACAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}MACAddress;

//4�ֽڵ�IP��ַ
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
    u_char  ver_ihl;//�汾��4bits���Ͱ�ͷ���ȣ�4bits��
    u_char  tos;//��������
    u_short tlen;//�ܳ���
    u_short identification;//��ʶ
    u_short flags_fo;//��־��Ƭƫ��
    u_char  ttl;//��������
    u_char  proto;//Э��
    u_short crc;//ͷ��У���
    IPAddress  saddr;//ԴIP��ַ
    IPAddress  daddr;//Ŀ��IP��ַ
    u_int  op_pad;//ѡ��+���
}IPHeader;
#pragma pack()

//�ص�����������
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
    pcap_if_t* alldevs;//���ڴ洢���е��豸
    pcap_if_t* d;//���ڱ��������豸
    int dev_num;//Ҫ�򿪵ڼ����豸
    int i = 0;//ѭ������
    pcap_t* adhandle;//�򿪵�����ӿ��豸
    char errbuf[PCAP_ERRBUF_SIZE];//�洢������Ϣ��buffer
    u_int netmask;//��������
    char packet_filter[] = "ip";//��������ֻ����ip���ݰ�
    struct bpf_program fcode;

    //����NPcap��غ��������û�м��سɹ�����ô���������Ϣ���˳�����
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap���ش���\n");
        exit(1);
    }
     
    //��ȡ�����豸�б��������-1��˵������ִ��ʧ�ܣ����������Ϣ���˳�����
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs_exִ��ʧ��: %s\n", errbuf);
        exit(1);
    }

    int count_dev = 0;
    //����豸�б�����count_dev���м���
    for (d = alldevs; d; d = d->next)
    {
        count_dev++;
        printf("%d. %s", count_dev, d->name);
        if (d->description)//���豸������
            printf(" (%s)\n", d->description);
        else
            printf(" (������)\n");
    }

    //����豸�б�Ϊ�գ��������ʾ��Ϣ������������-1
    if (count_dev == 0)
    {
        printf("\nû���ҵ��豸\n");
        return -1;
    }

    //�����豸�ı��
    printf("�����豸�ı��:");
    scanf_s("%d", &dev_num);

    //���dev_num�ĺϷ���
    if (dev_num < 1 || dev_num > count_dev)
    {
        printf("\n����ı�ų�����Χ��\n");
        pcap_freealldevs(alldevs);//�ͷ����е��豸
        return -1;
    }

    //��d����Ϊѡ����豸
    for (d = alldevs, i = 0; i < dev_num - 1; d = d->next, i++);

    //����pcap_open,��ѡ��������ӿ��豸������һ��ָ��pcap_t���͵ľ��adhandle
    if ((adhandle = pcap_open(
        d->name, //�ӿ��豸������
        65536, // ��ʾҪ��������ݰ�������С��65536 ��ʾ�������е�����
        PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
        1000, // ��ʱʱ��
        NULL, // Զ����֤
        errbuf // error buffer
        )) == NULL)
    {
        fprintf(stderr,"\n��ѡ��������ӿ��豸ʧ��\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //��ȡ����ӿ��豸����������
    if (d->addresses != NULL)
    {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }   
    else
    {
        //�����豸��һ��C��������
        netmask = 0xffffff;
    }


    //�����������ݰ�������
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n����������ʧ��\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //�����ѱ�����������ݰ���������
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n���������ô���\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n���ڲ������ݰ��� %s ��...\n", d->description);
    pcap_freealldevs(alldevs);

    //�������ݰ�
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}
//�ص�������ʵ��
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    FrameHeader* fh;
    IPHeader* ih;

    //��pkt_data�л�ȡfh
    fh = (FrameHeader*)pkt_data;
    
    //��pkt_data�л�ȡih
    ih = (IPHeader*)(pkt_data + 14); 

    //�����Ϣ
    printf("ԴIP��ַ��%d.%d.%d.%d ->Ŀ��IP��ַ�� %d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,

        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4
        );
    printf("ԴMAC��ַ��%d.%d.%d.%d.%d.%d ->Ŀ��MAC��ַ��%d.%d.%d.%d.%d.%d\n",
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
    printf("\t����֡���ͣ�%d\n", fh->type);
    printf("\t�������ͣ�%d\n", ih->tos);
    printf("\t�ܳ��ȣ�%hu\n", ih->tlen);
}