#include "PEAnalysis.h"
#include <cstdio>
#include<cstring>

//构造函数
PEAnalysis::PEAnalysis(const char* FilePath)
{
	//打开文件 获取句柄
	HANDLE hFile = CreateFileA(FilePath, GENERIC_READ,FALSE,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);

	//判断文件是否打开失败
	if(hFile== INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"文件不存在", 0, 0);
	}

	//获取文件大小 
	DWORD dwSize = GetFileSize(hFile,NULL);

	//根据得到的字符串大小申请堆空间
	m_pFile = new char[dwSize] {};

	//从句柄读取数据到 pFile内
	DWORD dwRead=0;
	int result=ReadFile(hFile, m_pFile, dwSize, &dwRead, NULL);
	if (result == 0) {
		delete[] m_pFile;
		return;
	}

	//获取NT头
	m_pDos=(PIMAGE_DOS_HEADER)m_pFile;
	m_pNT = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pFile);

	
}

//析构函数
PEAnalysis::~PEAnalysis()
{
	delete[] m_pFile;
}

//判断是否是PE文件
BOOL PEAnalysis::IsPE()
{
	if(m_pDos->e_magic!=IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	if(m_pNT->Signature!=IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

DWORD PEAnalysis::RvAToFoA(DWORD c_RvA)
{
	
	//2.获取第一个区段首地址
	PIMAGE_SECTION_HEADER pSection=IMAGE_FIRST_SECTION(m_pNT);

	for(int i=0;i<m_pNT->FileHeader.NumberOfSections;i++)
	{
		if(c_RvA >= pSection->VirtualAddress && c_RvA < (pSection->VirtualAddress + pSection->SizeOfRawData))
		{
			return c_RvA - pSection->VirtualAddress + pSection->PointerToRawData+((DWORD)m_pFile);
		}
		pSection++;
	}

	return -1;
	
}

void PEAnalysis::ShowInfo()
{
	//标准头
	printf("文件运行平台:%08x\n",m_pNT->FileHeader.Machine);
	printf("区段数量    :%08x\n",m_pNT->FileHeader.NumberOfSections);
	printf("扩展头大小  :%08x\n",m_pNT->FileHeader.SizeOfOptionalHeader);
	printf("PE文件的属性:%08x\n",m_pNT->FileHeader.Characteristics);

	//扩展头
	printf("标志这是一个32位  :%08x\n", m_pNT->OptionalHeader.Magic);			    
	printf("所有代码区段      :%08x\n", m_pNT->OptionalHeader.SizeOfCode);     		
	printf("（OEP）程序入口点 :%08x\n", m_pNT->OptionalHeader.AddressOfEntryPoint);	
	printf("默认加载基址	  :%08x\n", m_pNT->OptionalHeader.ImageBase);		    
	printf("内存块对齐粒度 	  :%08x\n", m_pNT->OptionalHeader.SectionAlignment);	
	printf("文件对齐粒度	  :%08x\n", m_pNT->OptionalHeader.FileAlignment);	    
	printf("（映像大小）	  :%08x\n", m_pNT->OptionalHeader.SizeOfImage);			
	printf("所有头部大小	  :%08x\n", m_pNT->OptionalHeader.SizeOfHeaders);	    
	printf("程序              :%08x\n", m_pNT->OptionalHeader.Subsystem);			
	printf("DLL特征的标志 	  :%08x\n", m_pNT->OptionalHeader.DllCharacteristics);		
	printf("数据目录表的数量  :%08x\n",m_pNT->OptionalHeader. NumberOfRvaAndSizes);	

	//显示所有区段信息

	//获取第一个区段首地址
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(m_pNT);

	char str[9]= {};

	for (int i = 0; i < m_pNT->FileHeader.NumberOfSections; i++)
	{
		memcpy(str, pSec->Name, 8);
		printf("区段名称:%s\n", str);
		 printf("没有对齐的 实际大小  :%08x\n", pSec->Misc.VirtualSize);	
		 printf("当前区段首地址的RVA  :%08x\n", pSec->VirtualAddress);	
		 printf("区段文件对齐的大小   :%08x\n", pSec->SizeOfRawData);		
		 printf("区段首地址的文件偏移 :%08x\n", pSec->PointerToRawData);	      
		 printf("区块属性（RWX)       :%08x\n",pSec->Characteristics	);	
		 putchar('\n');
		pSec++;
	}

}

//导出表
void PEAnalysis::Export_Surface()
{
	//1.获取数据目录表第一个字段 得到导出表RVA
	DWORD pExportDir=m_pNT->OptionalHeader.DataDirectory[0].VirtualAddress;

	//2.获取导出表文件位置
	PIMAGE_EXPORT_DIRECTORY l_pExport=(PIMAGE_EXPORT_DIRECTORY)RvAToFoA(pExportDir);

	//3.获取PE文件名称
	printf("%s\n", (char*)RvAToFoA(l_pExport->Name));

	//4.获取序号基数
	printf("序号基数:%08x\n",l_pExport->Base);

	//5.遍历输出所有导出函数

	//5.1导出函数总个数
	DWORD FunLen = l_pExport->NumberOfFunctions;

	//5.2导出函数名称个数
	DWORD NameFunLen = l_pExport->NumberOfNames;

	//6.获取三个函数地址表地址
	PDWORD pFunAddress = (PDWORD)RvAToFoA(l_pExport->AddressOfFunctions);
	PDWORD pFunName = (PDWORD)RvAToFoA(l_pExport->AddressOfNames);
	PWORD  pOrdinals = (PWORD)RvAToFoA(l_pExport->AddressOfNameOrdinals);

	//遍历输出所有导出函数

	for(int i=0;i<FunLen;i++)
	{
		//如果函数地址为0 说明函数地址无效 寻找下一个
		if (pFunAddress[i] == 0)
			continue;
		
		printf("函数序号:%d\t", i + l_pExport->Base);

		bool Flag = false;
		for(int j=0;j<NameFunLen;j++)
		{
			if(pOrdinals[j]==i)
			{
				printf("函数名称:%s\t",(char*)RvAToFoA(pFunName[j]));
				Flag = true;
			}
			
		}
		if(!Flag)
			printf("函数名称:没有\t");

		printf("函数地址:%08x\n", RvAToFoA(pFunAddress[i]));

	}


}
