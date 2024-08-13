#pragma once
/******************************************************************************
       Module: logger.h
     Engineer: Arjun Suresh
  Description: Logging Class
  Date           Initials    Description
  08-Dec-2022    AS          Initial
******************************************************************************/
#include <stdio.h>
#include <stdarg.h>
#include <iostream>
#include <chrono>
#include <mutex>

/********************** NOTE ON USAGE *****************************
// To enable logging set the preprocessor macro _LOGGING_ENABLED
// _LOGGING_ENABLED=0 --> Disable Logging
// _LOGGING_ENABLED=1 --> Enable Logging

// To set the log level use the preprocessor macro _LOGGING_LEVEL
// _LOGGING_LEVEL = 0 --> LOG_DEBUG
// _LOGGING_LEVEL = 1 --> LOG_INFO
// _LOGGING_LEVEL = 2 --> LOG_WARN
// _LOGGING_LEVEL = 3 --> LOG_ERR
// _LOGGING_LEVEL = 4 --> LOG_FATAL
*******************************************************************/

// Log Level
enum TLogLevel
{
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERR = 3,
    LOG_FATAL = 4
};

#define LOGSTR_MAXLEN 1024              // Max Length of a single log message
#define DEFAULT_LOG_FILE "profiler_log.txt"      // Default log file name

// Check if Logging is enabled
// Only Add logs if it is enabled
#if (_LOGGING_ENABLED == 1)
    #define LOG_INIT(config) Logger::GetInstance().InitLogger(config);
    #define LOG_DEBUG(...)   Logger::GetInstance().Log(LOG_DEBUG, "DEBUG", __FILE__, __FUNCTION__, __VA_ARGS__)
    #define LOG_INFO(...)    Logger::GetInstance().Log(LOG_INFO,  "INFO",  __FILE__, __FUNCTION__, __VA_ARGS__)
    #define LOG_WARN(...)    Logger::GetInstance().Log(LOG_WARN,  "WARN",  __FILE__, __FUNCTION__, __VA_ARGS__)
    #define LOG_ERR(...)     Logger::GetInstance().Log(LOG_ERR,   "ERROR", __FILE__, __FUNCTION__, __VA_ARGS__)
    #define LOG_FATAL(...)   Logger::GetInstance().Log(LOG_FATAL, "FATAL", __FILE__, __FUNCTION__, __VA_ARGS__)
#else
    #define LOG_INIT(config) Logger::GetInstance().InitLogger(config);
    #define LOG_DEBUG(...)   
    #define LOG_INFO(...)    
    #define LOG_WARN(...)    
    #define LOG_ERR(...)
    #define LOG_FATAL(...)
#endif

// Logger class to handle all logging functionality
class Logger
{
public:
    // Error Codes
    enum TLogErr
    {
        LOGGER_OK,
        LOGGER_CANNOT_OPEN_FILE,
        LOGGER_ERR
    };
    // Logger Config Parameters
    struct TLoggerConfig
    {
        TLogLevel log_level;
        std::string log_file_path;
        TLoggerConfig()
        {
             log_level = LOG_ERR;
             log_file_path = DEFAULT_LOG_FILE;
        }
    };
    // Returns the singleton instance of logger
    static Logger& GetInstance()
    {
        static Logger s_logger;
        return s_logger;
    }
    // Initializes the logger
    TLogErr InitLogger(TLoggerConfig &config);
    // Function that performs logging
    TLogErr Log(TLogLevel log_level, const char *log_level_str, const char *file_name, const char *func_name, const char *fmt, ...);
    // Destructor
    ~Logger();
private:
    // Private Constructor
    Logger();
    // Private Copy Constructor
    Logger(Logger &);
    // Mutex to sync file writes
    std::mutex m_file_write_mutex;
    // Log File Object
    FILE* m_log_file = NULL;
    // Stores the logger config
    TLoggerConfig m_logger_config;
};
