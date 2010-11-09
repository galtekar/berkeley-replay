#include <stdio.h>
#include <sstream>
#include <iostream>

#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <vector>
void *savedPtr;

template <class Handler> class Event : public Handler {
public:
   unsigned int i;
   Event() {
      i = 4;
   }

   void run() {
      Handler::handle();
   }
   virtual void post()=0;
};

class ReceiveHandler {
public:
   void handle() {
      printf ("receive\n");
   }
};

class ReceiveEvent : public Event<ReceiveHandler> {
private:
   unsigned int &refi;
public:
   ReceiveEvent() : refi(i) {
   }

   virtual void pre() {
   }

   void post() {
      printf("refi = %d\n", refi);
      refi = 5;
      printf("i = %d\n", i);
      pre();
   }
};

class Base : public ReceiveEvent {
   void pre() {
      printf("base pre\n");
   }
};

class Derived : public Base {
public:
   void pre() {
      printf("derived pre\n");
   }
};

template <class H> void HandleEvent(Event<H>* evp) {
   evp->run();

   evp->post();
}

void dummy()
{
   Derived rev;

   HandleEvent(&rev);
}

int main()
{

   dummy();

   std::string s;

   s = "asdfsdf";

   return 0;
}
