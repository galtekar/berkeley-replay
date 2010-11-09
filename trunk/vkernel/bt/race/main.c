#include "vkernel/public.h"
#include "private.h"

#if 0
static void
ModRaceDetectPrintUsage()
{
   printf("race-detect!\n");
}

static int
ModRaceDetectParseOptions(int argc, char ** argv)
{
   int c, err = 0;

   VCPU_SetModeFlag(VCPU_MODE_RACEDETECT);

   while (1) {
      int option_index = 0;
      static struct option long_options[] = {
         {"memtrace-only", 0, NULL, 'm'},
         {0, 0, NULL, 0}
      };
      c = getopt_long(argc, argv, "m", long_options, &option_index);
      if (c == -1) {
         break;
      }

      switch (c) {
      case 'm':
         statsTraceButDontAddToSegment = 1;
         break;
      case '?': /* unrecognized options */
      default:
         err = -1;
         break;
      }
   }

   if (err == -1) {
      ModRaceDetectPrintUsage();
   }

   return err;
}
MODULE_ANALYSIS(racer,
      "Detects dynamic races",
      &ModRaceDetectParseOptions,
      &ModRaceDetectPrintUsage);
#endif

static int
RaceDetect_Init()
{
   if (VCPU_TestMode(VCPU_MODE_RACEDETECT)) {
      if (!VCPU_TestMode(VCPU_MODE_WANT_BT)) {
         FATAL("Race detection can only be done in BT mode.\n");
      }

      if (!VCPU_IsReplaying()) {
         FATAL("Race detection supported only during replay for now.\n");
         ASSERT_UNIMPLEMENTED(0);
      }
   } 

   MemTrace_Init();

   SegEvent_Init();

   Segment_Init();

   return 0;
}

BT_INITCALL(RaceDetect_Init);
