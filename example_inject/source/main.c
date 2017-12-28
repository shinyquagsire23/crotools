// This is an example for Smash 4's menu/menu CRO

extern void _ZN3app17BootSequenceSceneC1Ev_orig(void);

// Override _ZN3app17BootSequenceSceneC1Ev, the original function will be renamed to
// _ZN3app17BootSequenceSceneC1Ev_orig and can be (optionally) called
void _ZN3app17BootSequenceSceneC1Ev(void)
{
   // Pre-hook stuff
   
   // Call the original function
   _ZN3app17BootSequenceSceneC1Ev_orig();
   
   // Post-hook stuff
}
