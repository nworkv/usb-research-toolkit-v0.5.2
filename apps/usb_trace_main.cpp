#include "usb_research/trace.hpp"
#include <iostream>
#include <stdexcept>
using namespace usb_research;
static void usage(){std::cout<<"usb-trace - JSONL trace inspection and comparison\n\nUsage:\n  usb-trace summarize <trace.jsonl>\n  usb-trace compare <device.jsonl> <host-normalized.jsonl>\n";}
int main(int argc,char**argv){try{if(argc<3){usage();return 2;}std::string cmd=argv[1];if(cmd=="summarize"){std::cout<<summarize_trace(argv[2]).dump(2)<<"\n";return 0;}if(cmd=="compare"){if(argc!=4)throw std::runtime_error("compare requires exactly device and host JSONL files");std::cout<<compare_traces(argv[2],argv[3]).dump(2)<<"\n";return 0;}usage();return 2;}catch(const std::exception&e){std::cerr<<"usb-trace: "<<e.what()<<"\n";return 2;}}
