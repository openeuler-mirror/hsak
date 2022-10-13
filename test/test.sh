#!/bin/bash

#/*
# * Copyright (c) Huawei Technologies Co., Ltd. 2019-2022. All rights reserved.
# * hsak is licensed under the Mulan PSL v2.
# * You can use this software according to the terms and conditions of the Mulan PSL v2.
# * You may obtain a copy of Mulan PSL v2 at:
# *     http://license.coscl.org.cn/MulanPSL2
# * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# * PURPOSE.
# * See the Mulan PSL v2 for more details.
# * Description: test framework for hsak
# * Author: suweifeng <suweifeng1@huawei.com>
# * Create: 2019-09-15
#*/

usage()
{
    echo "Usage: sh test.sh [OPTIONS]"
    echo "Use test.sh to control test operation"
    echo
    echo "Misc:"
    echo "  -h, --help                      Print this help, then exit"
    echo  
    echo "Compile Options:"
    echo "  -m, --cmake <option>            use cmake genenate Makefile, eg: -m(default), -mcoverage, -masan, --cmake, --cmake=coverage"
    echo "  -c, --compile                   Enable compile"
    echo "  -e, --empty                     Enable compile empty(make clean)"
    echo  
    echo "TestRun Options"
    echo "  -r, --run <option>          Run all test, eg: -r, -rscreen(default), -rxml, --run, --run=screen, --run=xml"
    echo "  -s, --specify FILE          Only Run specify test executable FILE, eg: -smemory_test, --specify=memory_test"
    echo  
    echo "Coverage Options"
    echo "  -t, --cover-report <option>     Enable coverage report. eg: -t, -thtml(default), -ttxt, --cover-report, --cover-report=html, --cover-report=txt"
    echo "  -f, --cover-file FILE           Specified FILE coverage report, eg: -fmemory.c, --cover-file=memory.c"
    echo
}

ARGS=`getopt -o "hcer::m::t::s:f:" -l "help,cmake::,empty,cover-report::,run::,specify:,cover-file:" -n "test.sh" -- "$@"`
if [ $? != 0 ]; then
    usage
    exit 1
fi

eval set -- "${ARGS}"

if [ x"$ARGS" = x" --" ]; then
    # set default value
    COMPILE_ENABLE=no
    COVERAGE_ENABLE=no
    ASAN_ENABLE=no
    CLEAN_ENABLE=no
    RUN_TEST=yes
    RUN_MODE=screen # value: screen or xml
    COVER_REPORT_ENABLE=no
fi

while true; do
    case "${1}" in
        -h|--help)
            usage; exit 0;;
        -m|--cmake)
            CMAKE_ENABLE=yes
            case "$2" in
                "") shift 2;;
                coverage) COVERAGE_ENABLE=yes; shift 2;;
                asan) ASAN_ENABLE=yes; shift 2;;
                *) echo "Error param: $2"; exit 1;;
            esac;;
        -c|--compile)
            COMPILE_ENABLE=yes
            shift;;
        -e|--empty)
            CLEAN_ENABLE=yes
            shift;;
        -r|--run)
            RUN_TEST=yes
            case "$2" in
                "") RUN_MODE=screen; shift 2;;
                screen) RUN_MODE=screen; shift 2;;
                xml) RUN_MODE=xml; shift 2;;
                *)echo "Error param: $2"; exit 1;;
            esac;;
        -t|--cover-report)
            COVER_REPORT_ENABLE=yes
            case "$2" in
                "") COVER_STYLE=html;shift 2;;
                html) COVER_STYLE=html;shift 2;;
                txt) COVER_STYLE=txt;shift 2;;
                *)echo "Error param: $2"; exit 1;;
            esac;;
        -s|--specify)
            SPECIFY=$2
            shift 2;;
        -f|--cover-file)
            COVER_FILE=$2
            shift 2;;
        --)
            shift; break;;
    esac
done

function test_clean()
{
    echo ---------------------- clean begin ----------------------
    set -x
    rm ../build -rf
    set +x
    echo ---------------------- clean end ------------------------
}

function test_cmake()
{
    local CMAKE_OPTION="-DCMAKE_BUILD_TYPE=Debug"

    echo ---------------------- cmake begin ----------------------
    if [ x"${COVERAGE_ENABLE}" = x"yes" ]; then
        CMAKE_OPTION="${CMAKE_OPTION} -DCOVERAGE_ENABLE=1"
    fi

    if [ x"${ASAN_ENABLE}" = x"yes" ]; then
        CMAKE_OPTION="${CMAKE_OPTION} -DASAN_ENABLE=1"
    fi

    if [ ! -d ../build ]; then
        mkdir ../build
    fi

    cd ../build
    cmake .. ${CMAKE_OPTION}
    cd -
    echo ---------------------- cmake end ------------------------
    echo
}

function test_compile()
{
    echo ---------------------- compile begin ----------------------
    if [ -d ../build ]; then
        cd ..
        make
        cd -
    else
        echo "<build> directory not exist, pls check!"
    fi
    echo ---------------------- compile end ------------------------
    echo
}

function test_run_all()
{
    echo ---------------------- run test begin --------------------------
    
    if [ x"${RUN_MODE}" = x"screen" ]; then
        RUN_MODE=0
    elif [ x"${RUN_MODE}" = x"xml" ]; then
        RUN_MODE=1
    elif [ x"${RUN_MODE}" = x"" ]; then
        RUN_MODE=0
    else
        echo "not suport run mode <${RUN_MODE}>"
        usage
        cd -
        exit 1
    fi

    if [ x"${SPECIFY}" = x"" ]; then
        SPECIFY=`find -name "*_llt"` # run all test
    else
        SPECIFY=`find -name "${SPECIFY}"` # run one test
    fi

    TEST_LOG=test_result.log
    >$TEST_LOG

    for TEST in $SPECIFY; do
        echo $TEST
        $TEST $RUN_MODE
        sleep 1
        if [ $? != 0 ];then
            echo $TEST FAILED >> $TEST_LOG
        else
            echo $TEST success >> $TEST_LOG
        fi  
    done
	
    echo ""
    echo '######################test result begin######################'
    cat $TEST_LOG
    echo '#######################test result end#######################'
    echo ""
    echo ---------------------- run test end --------------------------
    echo
    cd -
}

function generate_coverage()
{
    local target_dir=$(dirname `pwd`)
    
    echo ------------------ generate coverage begin --------------
    if [ x"${COVER_STYLE}" = x"txt" ]; then
        if [ ! -d ${target_dir}/build/coverage/txt ]; then 
            mkdir -p ${target_dir}/build/coverage/txt
        fi

        GCDAS=`find ${target_dir} -name "${COVER_FILE}.gcda"`
        echo ${COVER_FILE}.gcda
        if [ x"$GCDAS" = x"" ]; then
            echo "not find ${COVER_FILE}.gcda"
            echo
            cd -
            exit 1
        fi

        cd ${target_dir}/build/coverage/txt
        for GCDA in $GCDAS; do
            gcov $GCDA
        done
        cd -

        find ${target_dir} -name "*.h.gcov" | xargs rm -f
        echo '#################################'
        find ${target_dir} -name "${COVER_FILE}.gcov"
        echo '#################################'
    elif [ x"${COVER_STYLE}" = x"html" ]; then
        if [ -d ${target_dir}/build/coverage/html ]; then 
            rm -rf ${target_dir}/build/coverage/html
        fi
        mkdir -p ${target_dir}/build/coverage/html
        if [ x"${COVER_FILE}" = x"" ]; then
            LCOV_CMD="-d ${target_dir}"
        else
            GCDAS=`find ${target_dir} -name "${COVER_FILE}.gcda"`
            if [ $? != 0 ]; then
                echo "not match ${COVER_FILE}.gcda"
                exit  1
            fi

            for GCDA in ${GCDAS}; do
                TMP_STR=" -d ${GCDA}";
                LCOV_CMD="${LCOV_CMD} ${TMP_STR}";
            done
        fi

        # lcov -c ${LCOV_CMD} -o ${target_dir}/build/coverage/html/coverage.info --exclude '*_test.c' --include '*.c' --include '*.cpp' --include '*.cc' --rc lcov_branch_coverage=1 --ignore-errors gcov --ignore-errors source --ignore-errors graph
        lcov -c ${LCOV_CMD} -b $(dirname $(pwd)) --no-external --exclude '*_test.c' -o ${target_dir}/build/coverage/html/coverage.info --rc lcov_branch_coverage=1 --ignore-errors gcov --ignore-errors source --ignore-errors graph
        if [ $? != 0 ]; then
            echo "lcov generate coverage.info fail."
            exit  1
        fi

        genhtml ${target_dir}/build/coverage/html/coverage.info -o ${target_dir}/build/coverage/html --branch-coverage --rc lcov_branch_coverage=1 -s --legend --ignore-errors source
        if [ $? != 0 ]; then
            echo "genhtml fail."
            exit 1
        fi
        chmod 755 -R ${target_dir}/build/coverage/html
    fi
    echo ------------------ generate coverage end ----------------
}

start_seconds=$(date --date="`date +'%Y-%m-%d %H:%M:%S'`" +%s)

if [ x"${CLEAN_ENABLE}" = x"yes" ]; then
    test_clean
fi

if [ x"${CMAKE_ENABLE}" = x"yes" ]; then
    test_cmake
fi

if [ x"${COMPILE_ENABLE}" = x"yes" ]; then
    test_compile
fi

if [ x"${RUN_TEST}" = x"yes" ]; then
    test_run_all
fi

if [ x"${COVER_REPORT_ENABLE}" = x"yes" ]; then
    generate_coverage
fi

end_seconds=$(date --date="`date +'%Y-%m-%d %H:%M:%S'`" +%s)
echo "use seconds: "$((end_seconds-start_seconds))
