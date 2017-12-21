
extern int test(char* data, char* data_data);

char data[0x200];
char data_data[5] = {1,2,3,4,5};
const char rodata[6] = {6,5,4,3,2,1};

int _main(int argc, char **argv)
{
   int ret = test(data, data_data);
   
   switch(ret)
   {
      case 1:
         data[0] = 2;
         break;
      case 2:
         data[3] = 4;
         break;
      case 3:
         data[4] = 7;
         break;
      case 4:
         data[3] = 1;
         break;
      case 5:
         data[9] = 2;
         break;
      case 6:
         data[11] = 3;
         break;
      case 7:
         data[123] = 7;
         break;
      case 8:
         data[11] = 1;
         break;
      case 9:
         data[777] = 7;
         break;
      case 10:
         data[122] = 9;
         break;
      case 11:
         data[0] = 12;
         break;
      case 12:
         data[3] = 14;
         break;
      case 13:
         data[4] = 17;
         break;
      case 14:
         data[3] = 11;
         break;
      case 15:
         data[9] = 12;
         break;
      case 16:
         data[11] = 13;
         break;
      case 17:
         data[123] = 17;
         break;
      case 18:
         data[11] = 11;
         break;
      case 19:
         data[777] = 17;
         break;
      case 20:
         data[122] = _main;
         break;
   }
   
   test(data, data_data);
   
   return 0;
}
