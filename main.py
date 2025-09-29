# This is a sample Python script.

# Press Alt+Umschalt+X to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


from src.ghidra import Ghidra

def main():
    #ilename = "BXAU77A6ZAE5_X538_Pst-DCM_1_.hex"
    #filename = 'BMW_M235i_200rf_boost_cap_2300_650nm.bin'
    #filename = "eeeeer4.hex"
    filename = "8K2907115AF.bin"

    ghidra = Ghidra()
    with ghidra.open_program(filename) as flat_api:
        from src.find_a0 import Find_A0
        from src.find_a9 import Find_A9
        from src.helper import GhidraHelper
        helper = GhidraHelper(flat_api)
        find_a0 = Find_A0(flat_api, helper)
        arr = find_a0.find()
        find_a9 = Find_A9(flat_api, helper)
        a9 = find_a9.find()
        arr["a9"] = a9
        print(arr)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
