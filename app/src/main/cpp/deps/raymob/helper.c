/*
 *  raymob License (MIT)
 *
 *  Copyright (c) 2023 Le Juez Victor
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include "raymob.h"

/* Static variables */

static jobject featuresInstance = NULL;

/* Functions definition */

JNIEnv* AttachCurrentThread(void)
{
    JavaVM *vm = GetAndroidApp()->activity->vm;
    JNIEnv *env;

    (*vm)->AttachCurrentThread(vm, &env, NULL);
    return env;
}

void DetachCurrentThread(void)
{
    JavaVM *vm = GetAndroidApp()->activity->vm;
    (*vm)->DetachCurrentThread(vm);
}

jobject GetNativeLoaderInstance(void)
{
    return GetAndroidApp()->activity->clazz;
}

jobject GetFeaturesInstance(void)
{
    if (featuresInstance == NULL)
    {
        JNIEnv *env = AttachCurrentThread();
        jobject nativeLoaderInstance = GetNativeLoaderInstance();

        jclass nativeLoaderClass = (*env)->GetObjectClass(env, nativeLoaderInstance);
        jmethodID getFeaturesMethod = (*env)->GetMethodID(env, nativeLoaderClass, "getFeatures", "()Lcom/raylib/raymob/Features;");

        if (getFeaturesMethod == NULL) return NULL; // Handle the case where the method is not found

        jobject localFeaturesInstance = (*env)->CallObjectMethod(env, nativeLoaderInstance, getFeaturesMethod);
        featuresInstance = (*env)->NewGlobalRef(env, localFeaturesInstance);

        DetachCurrentThread();
    }

    return featuresInstance;
}