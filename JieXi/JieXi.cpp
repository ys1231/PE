#include <iostream>
#include"PEAnalysis.h"


int main()
{
    
	PEAnalysis pe("twain_32.dll");

	pe.IsPE();
	pe.ShowInfo();
	pe.Export_Surface();

}
