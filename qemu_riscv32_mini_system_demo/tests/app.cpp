/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(UI_TEST) || defined(ABILITY_TEST) || defined(HELLO_TEST) || defined(MATH_TEST) || defined(FILE_TEST) \
                     || defined(TCM_TEST) || defined(MALLOC_TEST) || defined(OPENHITLS_SM2_TEST) || defined(VTCM_TEST)
#include "ohos_init.h"
#include "ui_adapter.h"

#if defined(UI_TEST)
    #include "ui_test.h"
    #include "sample_ui.h"
#elif defined(ABILITY_TEST)
    #include "ability_test.h"
#endif

#if defined(HELLO_TEST)
    #include "hello_test.h"
#endif
#if defined(MATH_TEST)
    #include "math_test.h"
#endif
#if defined(FILE_TEST)
    #include "file_test.h"
#endif
#if defined(TCM_TEST)
    #include "tcm_test.h"
#endif
#if defined(MALLOC_TEST)
    #include "malloc_test.h"
#endif
#if defined(OPENHITLS_SM2_TEST)
    #include "openhitls_sm2_test.h"
#endif
#if defined(VTCM_TEST)
    #include "vtcm_scheduler_test.h"
#endif

void RunApp(void)
{
#ifdef UI_TEST
    AnimatorDemoStart();
#elif defined(ABILITY_TEST)
    StartJSApp();
#endif
}

void AppEntry(void)
{
    UiAdapterRun();
}
APP_FEATURE_INIT(AppEntry);

void AppHelloTaskInitEntry(void)
{
#if defined(HELLO_TEST)
    HelloTaskInit();
#endif
}
APP_FEATURE_INIT(AppHelloTaskInitEntry);

void AppMathTestEntry(void)
{
#if defined(MATH_TEST)
    MathTestApp();
#endif
}
APP_FEATURE_INIT(AppMathTestEntry);

void AppFileTestEntry(void)
{
#if defined(FILE_TEST)
    FileTestTaskApp();
    // FileTestThreadApp();
#endif
}
APP_FEATURE_INIT(AppFileTestEntry);

void AppTCMTestEntry(void)
{   
#if defined(TCM_TEST)
    TCMTestApp();
#endif 
}
APP_FEATURE_INIT(AppTCMTestEntry);

void AppMallocTestEntry(void)
{
#if defined(MALLOC_TEST)
    MallocTestTaskApp();
#endif
}
APP_FEATURE_INIT(AppMallocTestEntry);

void AppOpenHiTLSSM2TestEntry(void)
{
#if defined(OPENHITLS_SM2_TEST)
    HitlsSM2TestTaskApp();
#endif
}
APP_FEATURE_INIT(AppOpenHiTLSSM2TestEntry);

void AppVtcmTestEntry(void)
{
#if defined(VTCM_TEST)
    // CreateVtcmTasks();
    app_init();
#endif
}
APP_FEATURE_INIT(AppVtcmTestEntry);

#endif