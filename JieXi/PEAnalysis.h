#ifndef PEANALTSIS
#define PEANALTSIS

#include<Windows.h>

class PEAnalysis
{
public:
	//构造函数
	PEAnalysis(const char *FilePath);

	//析构函数
	~PEAnalysis();
public:
	//文件数据缓存
	char* m_pFile;

	//获取DOS头
	PIMAGE_DOS_HEADER m_pDos;

	//保存NT头
	PIMAGE_NT_HEADERS m_pNT;

public:
	//判断是否是PE文件
	BOOL IsPE();

	//RvAToFoA
	DWORD RvAToFoA(DWORD c_RvA);

	//显示重要的信息
	void ShowInfo();
	
	//导出表
	void Export_Surface();

};


#endif
