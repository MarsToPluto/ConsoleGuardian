#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <chrono>
#include <iomanip>      // For put_time
#include <sstream>      // For string streams
#include <ctime>
#include <filesystem>   // C++17 for path manipulation
#include <shlobj.h>     // For SHGetKnownFolderPath, FOLDERID_RoamingAppData
#include <atomic>       // For atomic<bool>
#include <system_error> // For std::system_error

//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------
const std::string APP_NAME = "CmdWrapper";
const std::string LAST_DIR_FILENAME = "LastExitedDirectory.txt";
const std::string LOG_DIR_NAME = "CmdWrapperLogs";
const char* DIR_MARKER = "__CW_DIR_MARKER__"; // Unique marker for directory detection
const DWORD READ_BUFFER_SIZE = 4096;
const DWORD PROCESS_EXIT_WAIT_MS = 5000; // Max time to wait for cmd.exe to exit gracefully

//-----------------------------------------------------------------------------
// Log Type Enum
//-----------------------------------------------------------------------------
enum class LogType {
    INFO,
    COMMAND,
    OUTPUT,
    ERROR,
    WARN
};

//-----------------------------------------------------------------------------
// Global Variables & Synchronization Objects
//-----------------------------------------------------------------------------
std::mutex g_stateMutex; // Protects g_currentDirectory
std::string g_currentDirectory = "";

std::atomic<bool> g_cmdExited = false; // Flag indicating the child process likely terminated
std::string g_sessionID = "";          // Unique ID for this session
std::filesystem::path g_logFilePath;   // Full path to the session's log file
std::ofstream g_logFileStream;         // Stream for writing to the log file
std::mutex g_logMutex;                 // Protects writing to the log file stream

// Pipe Handles (initialized to NULL)
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

// Process Handles (initialized to zero/NULL)
PROCESS_INFORMATION g_piProcInfo = {0};

//-----------------------------------------------------------------------------
// Forward Declarations
//-----------------------------------------------------------------------------

// Helper Functions
std::filesystem::path GetAppDataSubdir(const std::string& subdirName, bool create = true);
std::string LogTypeToString(LogType type);
std::string GetLastErrorStdStr(DWORD errorCode = GetLastError());

// Logging Functions
bool SetupLogging(); // Returns false on fatal logging setup error
void LogEntry(LogType type, const std::string& message);
void LogWinApiError(const std::string& context, DWORD errorCode = GetLastError());

// State Persistence
void LoadState();
void SaveState();

// Core Logic
void ReaderThread(HANDLE hChildStd_OUT);
bool SendCommandToCmd(const std::string& command); // Returns false on write failure

// Resource Management
void Cleanup();

//-----------------------------------------------------------------------------
// Helper Functions Implementation
//-----------------------------------------------------------------------------

/**
 * @brief Gets a subdirectory path within the application's directory in AppData/Roaming.
 * @param subdirName The name of the subdirectory (e.g., "CmdWrapperLogs"). Empty for base dir.
 * @param create If true, attempts to create the directory if it doesn't exist.
 * @return The full path to the subdirectory. Returns empty path on critical failure.
 */
std::filesystem::path GetAppDataSubdir(const std::string& subdirName, bool create) {
    PWSTR ppszPath = nullptr;
    std::filesystem::path baseAppDir;

    // Use Known Folders API first
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ppszPath);
    if (SUCCEEDED(hr)) {
        baseAppDir = std::filesystem::path(ppszPath) / APP_NAME;
        CoTaskMemFree(ppszPath); // Free memory allocated by SHGetKnownFolderPath
    } else {
        // Fallback to %APPDATA% environment variable
        char* appdataEnv = nullptr;
        size_t len = 0;
        errno_t err = _dupenv_s(&appdataEnv, &len, "APPDATA");
        if (err == 0 && appdataEnv != nullptr) {
            baseAppDir = std::filesystem::path(appdataEnv) / APP_NAME;
            free(appdataEnv);
        } else {
            // Last resort: relative to current path (not ideal for shared logs)
            std::cerr << "WARN: Could not determine Roaming AppData path. Using relative path './" << APP_NAME << "'." << std::endl;
            baseAppDir = std::filesystem::current_path() / APP_NAME;
        }
    }

    std::filesystem::path targetPath = subdirName.empty() ? baseAppDir : (baseAppDir / subdirName);

    if (create) {
        try {
            if (!std::filesystem::exists(targetPath)) {
                if (!std::filesystem::create_directories(targetPath)) {
                     std::cerr << "ERROR: Failed to create directory (check permissions): " << targetPath << std::endl;
                     return {}; // Return empty path on failure
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "ERROR: Filesystem error creating directory " << targetPath << ": " << e.what() << std::endl;
            return {}; // Return empty path on failure
        }
    }
    return targetPath;
}

/**
 * @brief Converts LogType enum to its string representation.
 */
std::string LogTypeToString(LogType type) {
    switch (type) {
        case LogType::INFO:    return "INFO";
        case LogType::COMMAND: return "CMD";
        case LogType::OUTPUT:  return "OUT";
        case LogType::ERROR:   return "ERR";
        case LogType::WARN:    return "WARN";
        default:               return "???";
    }
}

/**
 * @brief Gets the Windows error message string for a given error code.
 * @param errorCode The Windows error code (default: GetLastError()).
 * @return The formatted error message string.
 */
std::string GetLastErrorStdStr(DWORD errorCode) {
    if (errorCode == 0) {
        return "No error"; // Or perhaps "Success"
    }

    LPSTR lpMsgBuf = nullptr;
    DWORD dwChars = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0,
        NULL);

    std::string message = "Unknown error code";
    if (dwChars > 0 && lpMsgBuf != nullptr) {
        message = lpMsgBuf;
        // Remove trailing newline characters which FormatMessage often adds
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
            message.pop_back();
        }
        LocalFree(lpMsgBuf); // Free the buffer allocated by FormatMessage
    }
    return "(" + std::to_string(errorCode) + ") " + message;
}

//-----------------------------------------------------------------------------
// Logging Functions Implementation
//-----------------------------------------------------------------------------

/**
 * @brief Sets up the session ID and opens the log file stream.
 * @return true if logging setup was successful, false otherwise.
 */
bool SetupLogging() {
    // 1. Generate Session ID
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
    if (localtime_s(&now_tm, &now_c) != 0) {
         std::cerr << "ERROR: localtime_s failed during session ID generation." << std::endl;
         return false;
    }
    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y%m%d_%H%M%S");
    g_sessionID = "S_" + ss.str() + "_" + std::to_string(GetCurrentProcessId());

    // 2. Get log directory path (and create it)
    std::filesystem::path logDir = GetAppDataSubdir(LOG_DIR_NAME, true);
    if (logDir.empty()) {
         std::cerr << "ERROR: Failed to get or create log directory path. Logging disabled." << std::endl;
         return false;
    }
    g_logFilePath = logDir / ("Log_" + g_sessionID + ".log");

    // 3. Open log file stream
    std::lock_guard<std::mutex> logLock(g_logMutex); // Ensure exclusive access while opening
    g_logFileStream.open(g_logFilePath, std::ios::out | std::ios::app);
    if (!g_logFileStream.is_open()) {
        DWORD lastError = GetLastError(); // Get error code if available from underlying OS call
        std::cerr << "ERROR: Could not open log file: " << g_logFilePath
                  << ". Check permissions. System Error: " << GetLastErrorStdStr(lastError)
                  << ", Stream Error: " << std::system_category().message(errno) << std::endl;
        return false; // Fatal if we can't open the log file
    }

    // Log the successful start (this function now needs g_logFileStream to be open)
    LogEntry(LogType::INFO, "Session Started. Log file: " + g_logFilePath.string());
    return true;
}

/**
 * @brief Writes a formatted entry to the session's log file. Thread-safe.
 * @param type The type/level of the log entry.
 * @param message The message content to log.
 */
void LogEntry(LogType type, const std::string& message) {
    // Avoid logging if stream isn't open (e.g., during early init failure or after cleanup)
    if (!g_logFileStream.is_open()) return;

    // Get current time with milliseconds
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::tm now_tm;
    if (localtime_s(&now_tm, &now_c) != 0) {
        std::cerr << "WARN: localtime_s failed during log entry." << std::endl;
        // Potentially write a raw error to the log file here if needed, but avoid recursion
        return;
    }

    std::stringstream timestamp_ss;
    timestamp_ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    timestamp_ss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    // Safely get current directory snapshot
    std::string dirSnapshot;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        dirSnapshot = g_currentDirectory.empty() ? "<unknown>" : g_currentDirectory;
    }

    // Prevent interleaved writes from different threads using logMutex
    std::lock_guard<std::mutex> logLock(g_logMutex);
    try {
        // Check if stream is still good before writing
        if (!g_logFileStream.good()) {
             std::cerr << "ERROR: Log stream is not in a good state before writing. Log entry skipped." << std::endl;
             return; // Don't attempt to write
        }

        // Write the formatted log entry
        g_logFileStream << "[" << timestamp_ss.str() << "] [" << g_sessionID << "] ["
                       << LogTypeToString(type) << "] [" << dirSnapshot << "] "
                       << message << std::endl; // std::endl flushes the stream

        // Check for stream errors *after* write/flush attempt
        if (g_logFileStream.fail()) {
            std::cerr << "ERROR: Failed to write to log file: " << g_logFilePath << ". Error state flags: "
                      << g_logFileStream.rdstate() << ". Stream error: " << std::system_category().message(errno) << std::endl;
            // Attempt to clear error flags to possibly allow future writes
            g_logFileStream.clear();
        }
    } catch (const std::ios_base::failure& e) {
         std::cerr << "ERROR: Exception caught during log file I/O: " << e.what() << " Code: " << e.code() << std::endl;
         // Handle exception, potentially trying to recover or signal error
    } catch (const std::exception& e) {
         std::cerr << "ERROR: Generic exception caught while writing to log file: " << e.what() << std::endl;
    }
}

/**
 * @brief Logs a Windows API error with context.
 * @param context A string describing the operation that failed.
 * @param errorCode The error code (usually from GetLastError()).
 */
void LogWinApiError(const std::string& context, DWORD errorCode) {
    LogEntry(LogType::ERROR, context + " failed: " + GetLastErrorStdStr(errorCode));
}

//-----------------------------------------------------------------------------
// State Persistence Implementation
//-----------------------------------------------------------------------------

/**
 * @brief Loads the last known directory from the state file.
 */
void LoadState() {
    std::filesystem::path stateFilePath = GetAppDataSubdir("", false) / LAST_DIR_FILENAME; // Don't create dir just for reading
    if (stateFilePath.empty()) {
        LogEntry(LogType::WARN, "Could not determine state file path. Starting fresh.");
        return;
    }
    if (!std::filesystem::exists(stateFilePath)) {
        LogEntry(LogType::INFO, "State file not found. Starting fresh.");
        return;
    }

    std::ifstream stateFile(stateFilePath);
    if (stateFile.is_open()) {
        std::string loadedDir;
        if (std::getline(stateFile, loadedDir) && !loadedDir.empty()) {
            // Validate the directory before accepting it
            try {
                 std::error_code ec;
                 bool exists = std::filesystem::exists(loadedDir, ec);
                 if (ec) {
                      LogEntry(LogType::ERROR, "Filesystem error checking existence of loaded directory '" + loadedDir + "': " + ec.message());
                 } else if (exists) {
                     bool isDir = std::filesystem::is_directory(loadedDir, ec);
                      if (ec) {
                          LogEntry(LogType::ERROR, "Filesystem error checking if loaded directory is directory '" + loadedDir + "': " + ec.message());
                      } else if (isDir) {
                          std::lock_guard<std::mutex> lock(g_stateMutex);
                          g_currentDirectory = loadedDir;
                          LogEntry(LogType::INFO, "Loaded last directory: " + g_currentDirectory);
                      } else {
                         LogEntry(LogType::WARN, "Loaded path from state file exists but is not a directory: " + loadedDir);
                      }
                 } else {
                    LogEntry(LogType::WARN, "Loaded directory from state file does not exist: " + loadedDir);
                 }
            } catch (const std::exception& e) { // Catch potential exceptions from filesystem calls
                 LogEntry(LogType::ERROR,"Exception validating loaded directory '" + loadedDir + "': " + std::string(e.what()));
            }
        }
        stateFile.close();
    } else {
        // Log error only if the file existed but couldn't be opened
        LogEntry(LogType::ERROR, "Failed to open state file for reading (check permissions): " + stateFilePath.string());
    }
}

/**
 * @brief Saves the current directory to the state file.
 */
void SaveState() {
    std::filesystem::path stateFilePath = GetAppDataSubdir("", true) / LAST_DIR_FILENAME; // Create dir if needed for saving
    if (stateFilePath.empty()) {
         LogEntry(LogType::ERROR, "Cannot save state, failed to get state file path.");
         return;
    }

    std::ofstream stateFile(stateFilePath);
    if (stateFile.is_open()) {
        std::string dirToSave;
        { // Lock scope for reading g_currentDirectory
            std::lock_guard<std::mutex> lock(g_stateMutex);
            dirToSave = g_currentDirectory;
        }
        stateFile << dirToSave << std::endl;
        stateFile.close(); // Close before checking errors
        if (stateFile.fail()) { // Check error flags after closing
             LogEntry(LogType::ERROR, "Failed to write or close state file: " + stateFilePath.string());
        } else {
            if (!dirToSave.empty()) { // Don't log saving an empty directory unless needed
               LogEntry(LogType::INFO, "Saved last directory: " + dirToSave);
            }
        }
    } else {
        LogEntry(LogType::ERROR, "Failed to open state file for writing (check permissions): " + stateFilePath.string());
    }
}

//-----------------------------------------------------------------------------
// Core Logic Implementation
//-----------------------------------------------------------------------------

/**
 * @brief Thread function dedicated to reading output from the child process's stdout/stderr pipe.
 *        Ensures consecutive identical output lines are not logged repeatedly.
 * @param hChildStd_OUT Read handle for the child process's output pipe.
 */
void ReaderThread(HANDLE hChildStd_OUT) {
    char buffer[READ_BUFFER_SIZE];
    DWORD dwRead;
    std::string currentLineBuffer; // Buffer for assembling lines
    std::string potentialDirLine;  // Stores the line immediately preceding the DIR_MARKER
    std::string lastLoggedOutputLine = "<INIT_STATE_IGNORE>"; // Stores the last line logged as OUTPUT to prevent dupes

    LogEntry(LogType::INFO, "Reader thread started.");

    while (true) {
        dwRead = 0; // Reset read count
        BOOL bSuccess = ReadFile(hChildStd_OUT, buffer, READ_BUFFER_SIZE - 1, &dwRead, NULL);

        // Check for read failure or pipe closure
        if (!bSuccess || dwRead == 0) {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_BROKEN_PIPE) {
                 LogEntry(LogType::INFO, "CMD process pipe closed (BROKEN_PIPE). Reader thread exiting.");
            } else if (!bSuccess && lastError != ERROR_SUCCESS && lastError != ERROR_IO_PENDING) { // Ignore IO_PENDING if using overlapped I/O (not here)
                 LogWinApiError("ReadFile from CMD pipe failed", lastError);
            } else {
                 LogEntry(LogType::INFO, "ReadFile returned 0 bytes (pipe likely closed). Reader thread exiting.");
            }
            g_cmdExited = true; // Signal main thread
            break; // Exit the reading loop
        }

        // Null-terminate the buffer safely
        buffer[dwRead] = '\0';

        // Process the chunk read from the pipe
        std::string outputChunk(buffer);
        currentLineBuffer += outputChunk;

        // Process complete lines ending with newline
        size_t newlinePos;
        while ((newlinePos = currentLineBuffer.find('\n')) != std::string::npos) {
            std::string line = currentLineBuffer.substr(0, newlinePos);
            if (!line.empty() && line.back() == '\r') { // Trim trailing '\r'
                line.pop_back();
            }
            currentLineBuffer.erase(0, newlinePos + 1); // Remove processed line from buffer

            // Check for our directory marker
            if (line.find(DIR_MARKER) != std::string::npos) {
                // Marker found. The *previous* non-empty line should be the directory.
                if (!potentialDirLine.empty()) {
                     std::lock_guard<std::mutex> lock(g_stateMutex);
                     if (g_currentDirectory != potentialDirLine) {
                         g_currentDirectory = potentialDirLine;
                         LogEntry(LogType::INFO, "Directory updated to: " + g_currentDirectory);
                     }
                }
                potentialDirLine.clear();
                lastLoggedOutputLine = "<RESET_AFTER_MARKER>"; // Reset duplicate check context after marker
            } else {
                 // This is normal output or the line before the marker

                 // Always print to user's console
                 std::cout << line << std::endl;

                 // Log the output *only if different from the last logged output line*
                 if (line != lastLoggedOutputLine) {
                     LogEntry(LogType::OUTPUT, line);
                     lastLoggedOutputLine = line; // Update last logged line
                 }
                 // Store this line as a candidate for the directory if it's not empty
                 if (!line.empty()) {
                     potentialDirLine = line;
                 } else {
                     // Empty line received - reset potential directory
                     potentialDirLine.clear();
                 }
            }
        } // End while processing lines in buffer
    } // End while ReadFile succeeds

    LogEntry(LogType::INFO, "Reader thread finished.");
}

/**
 * @brief Sends a command string to the hidden cmd.exe process's stdin.
 * @param command The command string (without newline).
 * @return true if the write was successful, false otherwise.
 */
bool SendCommandToCmd(const std::string& command) {
    if (g_hChildStd_IN_Wr == NULL || g_hChildStd_IN_Wr == INVALID_HANDLE_VALUE) {
        LogEntry(LogType::ERROR, "Attempted to send command but CMD input pipe is closed or invalid.");
        return false;
    }

    // Log the command *before* sending (unless it's the marker echo, which is noise)
    bool isMarkerEcho = (command.find("echo ") == 0 && command.find(DIR_MARKER) != std::string::npos);
    if (!isMarkerEcho) {
       LogEntry(LogType::COMMAND, command);
    }


    std::string full_command = command + "\r\n"; // cmd.exe expects CRLF
    DWORD dwWritten = 0;

    BOOL bSuccess = WriteFile(g_hChildStd_IN_Wr, full_command.c_str(), (DWORD)full_command.length(), &dwWritten, NULL);

    if (!bSuccess || dwWritten != full_command.length()) {
        DWORD lastError = GetLastError();
        LogWinApiError("WriteFile to cmd stdin failed for command: '" + command + "'", lastError);
        // If pipe is broken, the process is likely gone
        if (lastError == ERROR_BROKEN_PIPE || lastError == ERROR_NO_SYSTEM_RESOURCES) {
             LogEntry(LogType::WARN, "Signaling cmd exit due to pipe write failure.");
             g_cmdExited = true; // Assume process is gone if pipe breaks
        }
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------
// Resource Management Implementation
//-----------------------------------------------------------------------------

/**
 * @brief Closes all global handles (pipes, process, thread) and the log file stream.
 */
void Cleanup() {
    LogEntry(LogType::INFO, "Starting resource cleanup...");

    // Close pipe handles - check validity before closing
    auto safeCloseHandle = [](HANDLE& h, const char* name) {
        if (h != NULL && h != INVALID_HANDLE_VALUE) {
            if (!CloseHandle(h)) {
                 LogWinApiError(std::string("CloseHandle(") + name + ")");
            }
            h = NULL; // Mark as closed
        }
    };

    // Order can matter: Close write ends parent holds first if possible
    safeCloseHandle(g_hChildStd_IN_Wr, "g_hChildStd_IN_Wr");
    safeCloseHandle(g_hChildStd_OUT_Wr, "g_hChildStd_OUT_Wr"); // Parent shouldn't hold this after CreateProcess, but check
    safeCloseHandle(g_hChildStd_IN_Rd, "g_hChildStd_IN_Rd");   // Parent shouldn't hold this after CreateProcess, but check
    safeCloseHandle(g_hChildStd_OUT_Rd, "g_hChildStd_OUT_Rd");

    // Close process and thread handles
    safeCloseHandle(g_piProcInfo.hThread, "g_piProcInfo.hThread");
    safeCloseHandle(g_piProcInfo.hProcess, "g_piProcInfo.hProcess");

    // Close log file stream (thread-safe lock)
    {
        std::lock_guard<std::mutex> logLock(g_logMutex);
        if (g_logFileStream.is_open()) {
            g_logFileStream.flush(); // Ensure buffer is written
            g_logFileStream.close();
             if (g_logFileStream.fail()) { // Check for errors after closing
                  // Can't use LogEntry here as the stream is closed/failed
                  std::cerr << "ERROR: Failed to flush or close log file stream correctly during cleanup." << std::endl;
             }
        }
    }
    // Don't call LogEntry after this point

    // Final message to console if possible
    std::cout << "\n[" << APP_NAME << "] Resource cleanup finished." << std::endl;
}

//-----------------------------------------------------------------------------
// Main Function
//-----------------------------------------------------------------------------
int main() {
    // 1. Initialize logging ASAP
    if (!SetupLogging()) {
        // Critical logging failure, exit
        return 1;
    }

    // 2. Load previous state (last directory)
    LoadState();

    // 3. Set up pipes
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE; // Allow handles to be inherited by child
    saAttr.lpSecurityDescriptor = NULL;

    // Create pipe for child process's STDOUT/STDERR
    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        LogWinApiError("CreatePipe for child stdout/stderr failed"); Cleanup(); return 1;
    }
    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) { // READ handle is NOT inherited
        LogWinApiError("SetHandleInformation for stdout read handle failed"); Cleanup(); return 1;
    }

    // Create pipe for child process's STDIN
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        LogWinApiError("CreatePipe for child stdin failed"); Cleanup(); return 1;
    }
    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) { // WRITE handle is NOT inherited
        LogWinApiError("SetHandleInformation for stdin write handle failed"); Cleanup(); return 1;
    }

    // 4. Prepare STARTUPINFO structure
    STARTUPINFO siStartInfo;
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;   // Child writes stderr to this pipe handle
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;  // Child writes stdout to this pipe handle
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;    // Child reads stdin from this pipe handle
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    siStartInfo.wShowWindow = SW_HIDE; // Hide the real cmd.exe window

    // 5. Determine initial directory for cmd.exe
    std::string initialDirStr; // Keep string object alive
    const char* initialDirPtr = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_currentDirectory.empty()) {
            initialDirStr = g_currentDirectory;
            initialDirPtr = initialDirStr.c_str();
        }
    }

    // 6. Create the child process (cmd.exe)
    TCHAR szCmdline[] = TEXT("cmd.exe");
    BOOL bSuccess = CreateProcess(
        NULL, szCmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
        initialDirPtr, &siStartInfo, &g_piProcInfo
    );

    if (!bSuccess) {
        LogWinApiError(std::string("CreateProcess failed (Initial Dir: ") + (initialDirPtr ? initialDirPtr : "<Default>") + ")");
        Cleanup(); return 1;
    }
    LogEntry(LogType::INFO, "cmd.exe process created (PID: " + std::to_string(g_piProcInfo.dwProcessId) + ")");

    // 7. Close parent's handles to the child's pipe ends that parent doesn't use
    // IMPORTANT: Failure to close these can lead to deadlocks or resource leaks.
    if (!CloseHandle(g_hChildStd_OUT_Wr)) LogWinApiError("CloseHandle(g_hChildStd_OUT_Wr) in parent after CreateProcess");
    g_hChildStd_OUT_Wr = NULL; // Mark as closed in parent
    if (!CloseHandle(g_hChildStd_IN_Rd)) LogWinApiError("CloseHandle(g_hChildStd_IN_Rd) in parent after CreateProcess");
    g_hChildStd_IN_Rd = NULL;  // Mark as closed in parent

    // 8. Start the reader thread
    std::thread reader(ReaderThread, g_hChildStd_OUT_Rd);

    // 9. Send initial command to get directory if not loaded/validated
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (g_currentDirectory.empty()) {
            LogEntry(LogType::INFO, "No valid initial directory loaded/set, querying cmd.exe...");
            // Send commands to determine initial CWD
            if (!SendCommandToCmd("cd") || !SendCommandToCmd("echo " + std::string(DIR_MARKER))) {
                LogEntry(LogType::ERROR, "Failed to send initial directory query commands.");
                // Consider exiting or continuing with unknown directory
            }
        } else {
            // Print the initial prompt based on loaded state
             std::cout << "\n" << g_currentDirectory << "> " << std::flush;
        }
    }

    // 10. Main Input Loop
    LogEntry(LogType::INFO, "Entering main input loop.");
    std::string userInput;
    while (!g_cmdExited) {
        // Print prompt safely
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            std::cout << "\n" << (g_currentDirectory.empty() ? "?" : g_currentDirectory) << "> " << std::flush;
        }

        // Read user input
        if (!std::getline(std::cin, userInput)) {
            if (std::cin.eof()) {
                 LogEntry(LogType::INFO, "Input stream reached EOF (Ctrl+Z/Ctrl+D). Signaling exit.");
            } else {
                 LogEntry(LogType::ERROR, "Input stream error occurred. Signaling exit.");
            }
            // Close the write pipe to signal cmd.exe if it's still open and we haven't already
            auto safeCloseWritePipe = [&]() {
                if (g_hChildStd_IN_Wr != NULL && g_hChildStd_IN_Wr != INVALID_HANDLE_VALUE) {
                    LogEntry(LogType::INFO, "Closing child stdin pipe due to input error/EOF.");
                    CloseHandle(g_hChildStd_IN_Wr);
                    g_hChildStd_IN_Wr = NULL; // Mark as closed
                }
            };
            safeCloseWritePipe();
            break; // Exit the loop
        }

        // Process user input
        if (userInput == "exit") {
            LogEntry(LogType::INFO, "User typed 'exit' command in wrapper.");
            SendCommandToCmd("exit"); // Tell cmd.exe to exit
            // Don't break immediately, wait for process to exit or timeout later
            // This allows processing of any final output from cmd.exe
        } else if (!userInput.empty()) {
            // Send the command to cmd.exe
            if (SendCommandToCmd(userInput)) {
                // Send commands to get updated directory after user command
                // Failures here are logged but don't necessarily stop the wrapper
                SendCommandToCmd("cd");
                SendCommandToCmd("echo " + std::string(DIR_MARKER));
            } else {
                 // SendCommandToCmd failed, likely pipe broken, g_cmdExited might be true.
                 LogEntry(LogType::WARN, "Failed to send user command to cmd.exe. It might have exited.");
                 // Loop will check g_cmdExited condition next iteration.
            }
        } else {
            // Empty input, just loop and reprint prompt.
        }
    } // End while (!g_cmdExited)

    LogEntry(LogType::INFO, "Exited main input loop.");

    // 11. Shutdown Sequence
    LogEntry(LogType::INFO, "Starting shutdown sequence...");

    // Ensure the reader thread finishes
    if (reader.joinable()) {
        LogEntry(LogType::INFO, "Waiting for reader thread to join...");
        reader.join();
        LogEntry(LogType::INFO, "Reader thread joined.");
    } else {
         LogEntry(LogType::WARN, "Reader thread was not joinable at shutdown.");
    }

    // Wait for the child process to exit
    if (g_piProcInfo.hProcess != NULL && g_piProcInfo.hProcess != INVALID_HANDLE_VALUE) {
        LogEntry(LogType::INFO, "Waiting for cmd.exe process (PID: " + std::to_string(g_piProcInfo.dwProcessId) + ") to exit (max " + std::to_string(PROCESS_EXIT_WAIT_MS) + "ms)...");
        DWORD waitResult = WaitForSingleObject(g_piProcInfo.hProcess, PROCESS_EXIT_WAIT_MS);
        if (waitResult == WAIT_OBJECT_0) {
             LogEntry(LogType::INFO, "cmd.exe process exited gracefully.");
        } else if (waitResult == WAIT_TIMEOUT) {
             LogEntry(LogType::WARN, "cmd.exe process did not exit within timeout. Consider terminating if needed.");
             // Optional: TerminateProcess(g_piProcInfo.hProcess, 1); // Forceful termination
        } else {
             LogWinApiError("WaitForSingleObject on cmd.exe process failed");
        }
    } else {
        LogEntry(LogType::INFO, "cmd.exe process handle already invalid or null during shutdown wait.");
    }

    // 12. Save the final state (directory)
    SaveState();

    // 13. Clean up all resources (pipes, handles, log file)
    Cleanup(); // Cleanup logs final message to console if possible

    // Final message outside cleanup context
    std::cout << "\n[" << APP_NAME << "] Session " << g_sessionID << " ended." << std::endl;
    return 0;
}