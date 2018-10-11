#!/usr/bin/env python
import os
import sys
import argparse
import subprocess
import filecmp
import difflib
import shutil
from distutils.spawn import find_executable

test_src_harness = 'harness.c'
test_dir = os.path.dirname(os.path.realpath(__file__))
test_sources = []
for file in os.listdir(test_dir):
    if os.path.splitext(file)[1] == '.s':
        test_sources.append(file)
clang_bin='clang'
llc_bin='llc'
clang_executable=None
llc_executable=None
generated_files=[]
generated_results=[]

def get_args():
    '''Get arguments'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Get script arguments')
    # Add arguments
    parser.add_argument(
        '-b', '--binary', type=str, help='test specified llvm-mctoll binary', required=True)
    parser.add_argument(
        '-l', '--llvm', type=str, help='directory with LLVM binaries', default=None)
    # Default is to not clean out artifacts created during the smoke-test
    # So, if -c is specified, the action is to set it to true
    parser.add_argument(
        '-c', '--clean', help='Clean all artifacts', action='store_true')
    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    test_bin = args.binary
    llvm_dir = args.llvm
    clean = args.clean
    print clean
    # Return all variable values
    return test_bin, llvm_dir, clean, parser

def main(argv):
    mctoll_binary, llvm_binary_dir, clean_after_run, argparser = get_args()
    # Check sanity llvm_binary_dir, if specified
    if llvm_binary_dir is None:
        # Make sure clang is available
        output = find_executable(clang_bin)
        if output:
            print "Using clang in command-line path"
        else:
            print "clang not found in path. Specify using -l option"
            argparser.print_help()
            sys.exit(-1)
        # Make sure clang is available
        output = find_executable(llc_bin)
        if output:
            print "Using llc in command-line path"
        else:
            print "llc not found in path. Specify using -l option"
            argparser.print_help()
            sys.exit(-1)
    else:
        if os.path.isdir(llvm_binary_dir):
            # Make sure clang is available
            clang_executable = os.path.join(llvm_binary_dir.rstrip(os.sep), clang_bin)
            if os.path.exists(os.path.join(clang_executable)):
                print "Using clang : " + clang_executable
            else:
                print "No clang found in " + llvm_binary_dir
                sys.exit(2)
            # Make sure llc is available
            llc_executable = os.path.join(llvm_binary_dir.rstrip(os.sep), llc_bin)
            if os.path.exists(os.path.join(llc_executable)):
                print "Using llc : " + llc_executable
            else:
                print "No llc found in " + llvm_binary_dir
                sys.exit(2)
        else:
            print "Directory " + llvm_binary_dir + " does not exist"
            sys.exit(2)

    # Compile assemble file to object file
    print "Looking in test directory " + test_dir
    for test_src_name in test_sources :
        test_src_full_path = os.path.join(test_dir.rstrip(os.sep), test_src_name)
        print "Compiling " + test_src_full_path
        subprocess.call([clang_executable, '-target', 'arm', '-c', test_src_full_path])
        # Add the .o to generated_files
        generated_files.append(os.path.splitext(test_src_name)[0]+'.o')

    # Compile harness.c to ARM object file
    harness_src_full_path = os.path.join(test_dir.rstrip(os.sep), test_src_harness)
    print "Compiling ARM " + harness_src_full_path
    subprocess.call([clang_executable, '-target', 'arm','-c', harness_src_full_path])
    os.rename(os.path.splitext(test_src_harness)[0]+'.o', os.path.splitext(test_src_harness)[0]+'_arm.o')
    # Add the .o to generated_files
    generated_files.append(os.path.splitext(test_src_harness)[0]+'_arm.o')

    # Link ARM object files with harness_arm.o to generate ARM executable file:
    base_executable = os.path.splitext(test_src_harness)[0]
    test_obj_list=[base_executable+'_arm.o']
    for test_src_name in test_sources :
        test_obj_list.append(os.path.splitext(test_src_name)[0]+'.o')

    print "Linking ",
    print test_obj_list
    subprocess.call([clang_executable,"--target=arm-linux-gnueabi", "-static", "-o", base_executable] + test_obj_list)
    # Add the base executable to generated_files
    generated_results.append(base_executable)

    # Raise test objects to generate .ll files
    for test_src_name in test_sources :
        test_name = os.path.splitext(test_src_name)[0]
        test_obj = test_name +'.o'
        raised_test_ll = test_name+"-dis.ll"
        #ll_output = open(raised_test_ll, "w")
        #Run mctoll on test-name.o to result in test-name-dis.ll
        #subprocess.call([mctoll_binary, '-d', test_obj], stdout=ll_output, stderr=ll_output)
        #Close file
        #ll_output.close()
        #Add the ll file to generated_files
        #generated_files.append(raised_test_ll)

        # Compile the ll files resulting from raising
        print "Raising " + raised_test_ll
        # Running llc -c test-name-dis.s
        subprocess.call([llc_executable, raised_test_ll])
        # Add the .s file to generated_files
        generated_files.append(test_name+'-dis.s')

        # Assemble the resulting .s to X86 object files using clang
        # Running clang -c test-name-dis.s
        subprocess.call([clang_executable, '-c', os.path.splitext(raised_test_ll)[0]+'.s'])
        # Add the .o file to generated_files
        generated_files.append(test_name+'-dis.o')

    # Compile harness.c to harness_x86.o
    print "Compiling X86 " + harness_src_full_path
    subprocess.call([clang_executable,'-c', harness_src_full_path])
    os.rename(os.path.splitext(test_src_harness)[0]+'.o', os.path.splitext(test_src_harness)[0]+'_x86.o')
    # Add the .o to generated_files
    generated_files.append(os.path.splitext(test_src_harness)[0]+'_x86.o')

    # Link harness_x86.o with X86 object files to generate harness-dis
    base_executable_dis = os.path.splitext(test_src_harness)[0]+'-dis'
    test_obj_list_dis=[base_executable+'_x86.o']
    for test_src_name in test_sources :
        test_obj_list_dis.append(os.path.splitext(test_src_name)[0]+'-dis.o')

    print "Linking ",
    print test_obj_list_dis
    subprocess.call([clang_executable, "-o", base_executable_dis] + test_obj_list_dis)
    # Add the generated executable file to generated_files
    generated_results.append(base_executable_dis)

    # Now compare the execution of harness and harness-dis
    gold_executable = './'+os.path.splitext(test_src_harness)[0]
    raised_executable = gold_executable+'-dis'
    gold_out_file_name = "gold_output"
    gold_output = open(gold_out_file_name, "w")
    print "Running " + gold_executable

    subprocess.call(['qemu-arm', gold_executable], stdout=gold_output)
    # Close file
    gold_output.close()
    # Add the generated output file
    generated_results.append(gold_out_file_name)
    raised_out_file_name = "raised_output"
    raised_output = open(raised_out_file_name, "w")

    print "Running " + raised_executable
    subprocess.call([raised_executable], stdout=raised_output)
    # Close file
    raised_output.close()
    # Add the generated output file
    generated_results.append(raised_out_file_name)

    # Compare gold output with raised execution output
    diff_file = "diff"
    if filecmp.cmp(gold_out_file_name, raised_out_file_name) :
        print "Tests PASSED"
    else :
        print "Tests FAILED"
        a = open('gold_output').readlines()
        b = open('raised_output').readlines()
        diff_result = open(diff_file, 'w+')
        stdout = diff_result
        diff = difflib.ndiff(a, b)
        stdout.writelines(diff)
        diff_result.close()

        generated_results.append(diff_file)

        diff_result = open(diff_file, 'r+')
        for line in diff_result:
            if line[0]=='-':
                print line.split(' ')[1]+' Failed!'

    # Move the generated files to corresponding folder
    if os.path.exists("imm_files"):
       shutil.rmtree("imm_files")
    if os.path.exists("results"):
       shutil.rmtree("results")

    os.mkdir("imm_files")
    os.mkdir("results")

    for f in generated_files:
        shutil.move(f, "imm_files")
    for r in generated_results:
        shutil.move(r, "results")

    if clean_after_run:
       print "Deleting all created artifacts ..."
       shutil.rmtree("imm_files")
       shutil.rmtree("results")

if __name__ == "__main__":
    main(sys.argv[1:])
