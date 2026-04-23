#pragma once
namespace spdlog { 
  class logger {}; 
  namespace level { enum level_enum { trace, debug, info, warn, err, critical, off }; }
  template<typename... Args> void log(level::level_enum, Args&&...) {}
}
