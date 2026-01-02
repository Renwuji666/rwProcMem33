#include <cstdio>
#include <string.h> 
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <memory>
#include <dirent.h>
#include <cinttypes>
#include <mutex>
#include "MapRegionHelper.h"
#include "MemSearchKit/MemSearchKitUmbrella.h"


using namespace MemorySearchKit;

int findPID(CMemoryReaderWriter *pDriver, const char *lpszCmdline) {
	int nTargetPid = 0;

	//驱动_获取进程PID列表
	std::vector<int> vPID;
	BOOL b = pDriver->GetPidList(vPID);
	printf("调用驱动 GetPidList 返回值:%d\n", b);

	//打印进程列表信息
	for (int pid : vPID) {
		//驱动_打开进程
		uint64_t hProcess = pDriver->OpenProcess(pid);
		if (!hProcess) { continue; }

		//驱动_获取进程命令行
		char cmdline[100] = { 0 };
		pDriver->GetProcessCmdline(hProcess, cmdline, sizeof(cmdline));

		//驱动_关闭进程
		pDriver->CloseHandle(hProcess);

		if (strcmp(lpszCmdline, cmdline) == 0) {
			nTargetPid = pid;
			break;
		}
	}
	return nTargetPid;
}


//演示多线程普通搜索
void normal_val_search(CMemoryReaderWriter *pRwDriver, uint64_t hProcess, size_t nWorkThreadCount) {

	//获取进程数据内存区域
	std::vector<MemRegionItem> vScanMemMaps;
	GetMemRegions(pRwDriver, hProcess,
		REGION_R0_0,
		vScanMemMaps);
	if (!vScanMemMaps.size()) {
		printf("无内存可搜索\n");
		//关闭进程
		pRwDriver->CloseHandle(hProcess);
		printf("调用驱动 CloseHandle:%" PRIu64 "\n", hProcess);
		fflush(stdout);
		return;
	}
	//准备要搜索的内存区域
	std::shared_ptr<MemSearchSafeWorkBlockWrapper> spvWaitScanMemBlock = std::make_shared<MemSearchSafeWorkBlockWrapper>();
	if (!spvWaitScanMemBlock) {
		return;
	}
	for (auto & item : vScanMemMaps) {
		spvWaitScanMemBlock->push_back(item.baseInfo.baseaddress, item.baseInfo.size, 0, item.baseInfo.size);
	}

	//首次搜索
	std::vector<ADDR_RESULT_INFO> vSearchResult; //搜索结果
	{
		SearchValue<float>(
			pRwDriver,
			hProcess,
			spvWaitScanMemBlock, //待搜索的内存区域
			0.33333334327f, //搜索数值
			0.0f,
			0.01, //误差范围
			SCAN_TYPE::ACCURATE_VAL, //搜索类型: 精确搜索
			nWorkThreadCount, //搜索线程数
			vSearchResult, //搜索后的结果
			4); //扫描的对齐字节数

		printf("共搜索出%zu个地址\n", vSearchResult.size());
	}
	//再次搜索
	if (vSearchResult.size()) {
		//将每个地址往后偏移20
		std::vector<ADDR_RESULT_INFO> vWaitSearchAddr; //待搜索的内存地址列表
		for (auto item : vSearchResult) {
			item.addr += 20;
			vWaitSearchAddr.push_back(item);
		}

		//再次搜索
		vSearchResult.clear();

		std::vector<ADDR_RESULT_INFO> vErrorList;
		SearchAddrNextValue<float>(
			pRwDriver,
			hProcess,
			vWaitSearchAddr, //待搜索的内存地址列表
			1.19175350666f, //搜索数值
			0.0f,
			0.01f, //误差范围
			SCAN_TYPE::ACCURATE_VAL, //搜索类型: 精确搜索
			nWorkThreadCount, //搜索线程数
			vSearchResult,
			vErrorList); //搜索后的结果
	}

	//再次搜索
	if (vSearchResult.size()) {
		//将每个地址往后偏移952
		std::vector<ADDR_RESULT_INFO> vWaitSearchAddr; //待搜索的内存地址列表
		for (auto item : vSearchResult) {
			item.addr += 952;
			vWaitSearchAddr.push_back(item);
		}

		//再次搜索
		vSearchResult.clear();
		std::vector<ADDR_RESULT_INFO> vErrorList;
		SearchAddrNextValue<int>(
			pRwDriver,
			hProcess,
			vWaitSearchAddr, //待搜索的内存地址列表
			-2147483648, //搜索数值
			0,
			0.01, //误差范围
			SCAN_TYPE::ACCURATE_VAL, //搜索类型: 精确搜索
			nWorkThreadCount, //搜索线程数
			vSearchResult, //搜索后的结果
			vErrorList);
	}

	//减少添加的地址
	std::vector<ADDR_RESULT_INFO> vTmpResultList;
	vTmpResultList.assign(vSearchResult.begin(), vSearchResult.end());
	for (auto& item : vSearchResult) {
		int offset = 952 + 20;
		if (item.addr < offset) {
			continue;
		}
		item.addr -= offset;
		vTmpResultList.push_back(item);
	}
	vSearchResult.clear();
	vSearchResult.assign(vTmpResultList.begin(), vTmpResultList.end());

	size_t count = 0;
	for (size_t i = 0; i < vSearchResult.size(); i++) {

		ADDR_RESULT_INFO addr = vSearchResult.at(i);
		printf("addr:%p\n", (void*)addr.addr);
		count++;
		if (count > 100) {
			printf("只显示前100个地址\n");
			break;
		}

	}
	printf("共偏移搜索出%zu个地址\n", vSearchResult.size());
	if (vSearchResult.size()) {
		printf("第一个地址为:%p\n", (void*)vSearchResult.at(0).addr);
	}

}

int main(int argc, char *argv[]) {
	printf(
		"======================================================\n"
		"本驱动名称: Linux ARM64 硬件读写进程内存驱动39\n"
		"本驱动接口列表：\n"
		"\t1.\t驱动_打开进程: OpenProcess\n"
		"\t2.\t驱动_读取进程内存: ReadProcessMemory\n"
		"\t3.\t驱动_写入进程内存: WriteProcessMemory\n"
		"\t4.\t驱动_关闭进程: CloseHandle\n"
		"\t5.\t驱动_获取进程内存块列表: VirtualQueryExFull（可选：显示全部内存、仅显示物理内存）\n"
		"\t6.\t驱动_获取进程PID列表: GetPidList\n"
		"\t7.\t驱动_提升进程权限到Root: SetProcessRoot\n"
		"\t8.\t驱动_获取进程物理内存占用大小: GetProcessPhyMemSize\n"
		"\t9.\t驱动_获取进程命令行: GetProcessCmdline\n"
		"\t10.\t驱动_隐藏驱动: HideKernelModule\n"
		"\t以上所有功能不注入、不附加进程，不打开进程任何文件，所有操作均为内核操作\n"
		"======================================================\n"
	);

	CMemoryReaderWriter rwDriver;

	//驱动默认隐蔽通信密匙
	std::string procNodeAuthKey = "e84523d7b60d5d341a7c4d1861773ecd";
	if (argc > 1) {
		//用户自定义输入驱动隐蔽通信密匙
		procNodeAuthKey = argv[1];
	}
	printf("Connecting rwDriver auth key:%s\n", procNodeAuthKey.c_str());

	//连接驱动
	int err = rwDriver.ConnectDriver(procNodeAuthKey.c_str());
	if (err) {
		printf("Connect rwDriver failed. error:%d\n", err);
		fflush(stdout);
		return 0;
	}

	const char *name = "com.miui.calculator";
	if (argc > 2) {
		name = argv[2];
	}
	//获取目标进程PID
	pid_t pid = findPID(&rwDriver, name);
	if (pid == 0) {
		printf("找不到进程\n");
		fflush(stdout);
		return 0;
	}
	printf("目标进程PID:%d\n", pid);
	//打开进程
	uint64_t hProcess = rwDriver.OpenProcess(pid);
	printf("调用驱动 OpenProcess 返回值:%" PRIu64 "\n", hProcess);
	if (!hProcess) {
		printf("调用驱动 OpenProcess 失败\n");
		fflush(stdout);
		return 0;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	size_t nWorkThreadCount = std::thread::hardware_concurrency() - 1;
	//仅执行普通搜索，避免遍历导致的崩溃
	normal_val_search(&rwDriver, hProcess, nWorkThreadCount);

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//关闭进程
	rwDriver.CloseHandle(hProcess);
	printf("调用驱动 CloseHandle:%" PRIu64 "\n", hProcess);
	fflush(stdout);
	return 0;
}
