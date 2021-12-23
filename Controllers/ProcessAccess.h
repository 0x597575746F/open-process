class ProcessAccess {
	std::vector<HANDLE> CsrssHandles;

	void* OldOpenProcess = nullptr;
	void* OldOpenThread = nullptr;

	static HANDLE WINAPI CopyProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
	static HANDLE WINAPI CopyThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);

	auto EnumerateCSRSSProcess() -> std::vector<HANDLE>;
	auto EnumerateSystemHandles(G::OBJECT_TYPE_NUMBER type_filter, const std::vector<HANDLE>& source_filter)->std::vector<G::SYSTEM_HANDLE>;
	auto FindProcessHandles(DWORD process_id)->HANDLE;
	auto FindThreadHandles(DWORD thread_id)->HANDLE;
public:
	static auto GetInstance()->ProcessAccess*;
	auto Attach()->void;
};
