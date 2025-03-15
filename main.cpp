#include <iostream>
#include "timgextractor.h"

int main(int argc, char* argv[])
{
    try
    {
        TImgExtractor imgExtractor(argc, argv);
        imgExtractor.ProcessPackets();
        if (imgExtractor.DataImgExist())
            imgExtractor.CreateImgFile();
        else
            std::cout << "There is no image in current data flow\n";
    }
    catch (std::exception& ex)
    {
        std::cerr << ex.what();
    }

    return 0;
}
