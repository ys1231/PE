#ifndef PEANALTSIS
#define PEANALTSIS

#include<Windows.h>

class PEAnalysis
{
public:
	//���캯��
	PEAnalysis(const char *FilePath);

	//��������
	~PEAnalysis();
public:
	//�ļ����ݻ���
	char* m_pFile;

	//��ȡDOSͷ
	PIMAGE_DOS_HEADER m_pDos;

	//����NTͷ
	PIMAGE_NT_HEADERS m_pNT;

public:
	//�ж��Ƿ���PE�ļ�
	BOOL IsPE();

	//RvAToFoA
	DWORD RvAToFoA(DWORD c_RvA);

	//��ʾ��Ҫ����Ϣ
	void ShowInfo();
	
	//������
	void Export_Surface();

};


#endif
