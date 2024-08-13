/******************************************************************************
       Module: logger.cpp
     Engineer: Arjun Suresh
  Description: Logging Class
  Date           Initials    Description
  08-Dec-2022    AS          Initial
******************************************************************************/
#include <string>
#include "logger.h"

/****************************************************************************
     Function: ~Logger
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Destructor
Date           Initials    Description
08-Dec-2022    AS          Initial
****************************************************************************/
Logger::~Logger()
{
    if (m_log_file)
    {
        fclose(m_log_file);
        m_log_file = NULL;
    }
}

/****************************************************************************
     Function: Logger
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: Contructor
Date           Initials    Description
08-Dec-2022    AS          Initial
****************************************************************************/
Logger::Logger()
{

}

/****************************************************************************
     Function: Logger
     Engineer: Arjun Suresh
        Input: Logger &
       Output: None
       return: None
  Description: Copy Contructor
Date           Initials    Description
08-Dec-2022    AS          Initial
****************************************************************************/
Logger::Logger(Logger &)
{

}

/****************************************************************************
     Function: InitLogger
     Engineer: Arjun Suresh
        Input: TLoggerConfig - config params
       Output: None
       return: TLogErr
  Description: Initializes the logger class
Date           Initials    Description
08-Dec-2022    AS          Initial
****************************************************************************/
Logger::TLogErr Logger::InitLogger(TLoggerConfig &config)
{
    m_logger_config = config;
    m_log_file = fopen(m_logger_config.log_file_path.c_str(), "a");
    if (!m_log_file)
    {
        return LOGGER_CANNOT_OPEN_FILE;
    }
    return LOGGER_OK;
}

/****************************************************************************
     Function: Log
     Engineer: Arjun Suresh
        Input: log_level - config params
               log_level_str - current log level string (DEBUG, INFO, ERROR, ...)
               file_name - File name from which log was called
               func_name - Function name from which log was called
               fmt - format
               ... - variable arguments
       Output: None
       return: TLogErr
  Description: Logs the data to file
Date           Initials    Description
08-Dec-2022    AS          Initial
****************************************************************************/
Logger::TLogErr Logger::Log(TLogLevel log_level, const char *log_level_str, const char *file_name, const char *func_name, const char *fmt, ...)
{
    // Default log level
    TLogLevel env_log_level = LOG_ERR;
    // If log level macro is set override log level
#ifdef _LOGGING_LEVEL
    env_log_level = (TLogLevel) _LOGGING_LEVEL;
#endif
    // Enable logging only if ENV_ENABLE_LOGGING environment variable is set
    if (std::getenv("ENV_ENABLE_LOGGING"))
    {
        // if log level env variable is set, override the log level
        const char *p_env_logging_level = std::getenv("ENV_LOGGING_LEVEL");
        if (p_env_logging_level)
        {
            env_log_level = (TLogLevel) std::stoi(p_env_logging_level);
        }
    }
    else
    {
        return LOGGER_OK;
    }

    if (m_log_file == NULL)
    {
        TLoggerConfig config;
        config.log_level = env_log_level;
        TLogErr ret = InitLogger(config);
        if (LOGGER_OK != ret)
            return ret;
    }

    if (m_log_file == NULL)
    {
        return LOGGER_CANNOT_OPEN_FILE;
    }

    if (log_level < m_logger_config.log_level)
    {
        return LOGGER_OK;
    }

    char buffer[LOGSTR_MAXLEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof buffer, fmt, ap);
    va_end(ap);

    // Get the Current Date & Time
    time_t timer;
    char time_info[32];
    struct tm *tm_info;
    timer = time(NULL);
    tm_info = localtime(&timer);
    strftime(time_info, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    // Write and Flush to file
    std::lock_guard<std::mutex> file_write_guard(m_file_write_mutex);
    fprintf(m_log_file, "[%s] [%s] [%s:%s] %s\n", log_level_str, time_info, file_name, func_name, buffer);
    fflush(m_log_file);
    return LOGGER_OK;
}
