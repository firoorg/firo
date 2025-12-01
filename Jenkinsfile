pipeline {
    agent {
        docker {
            image 'firoorg/firo-builder-depends:latest'
            alwaysPull true
        }
    }
    environment {
        CCACHE_DIR = '/tmp/.ccache'
        HOST = 'x86_64-linux-gnu'
    }
    stages {
        stage('Build dependencies') {
            steps {
                sh 'git clean -d -f -f -q -x'
                dir('depends') {
                    sh 'make -j`nproc` HOST=${HOST}'
                }
            }
        }
        stage('Build') {
            steps {
                sh '''
                    export HOST_TRIPLET=${HOST}
                    env PKG_CONFIG_PATH="$(pwd)/depends/$HOST_TRIPLET/lib/pkgconfig:$PKG_CONFIG_PATH" \\
                    cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/depends/$HOST_TRIPLET/toolchain.cmake \\
                    -DBUILD_CLI=ON -DBUILD_TESTS=ON -DBUILD_GUI=ON -DCMAKE_BUILD_TYPE=Release \\
                    -DCLIENT_VERSION_IS_RELEASE=true -DENABLE_CRASH_HOOKS=ON \\
                    -S$(pwd) -B$(pwd)/build
                '''
                dir('build') {
                    sh 'make -j`nproc`'
                }
            }
        }
        stage('Test') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE'){
                    dir('build') {
                        sh 'make test'
                    }
                }
            }
        }
        stage('Archive unit tests logs') {
            steps {
                script {
                    sh '''
                        mkdir -p test-logs
                        find build -name "LastTest.log" -exec cp {} test-logs/ctest-last.log \\; || true
                        find build -name "LastTestsFailed.log" -exec cp {} test-logs/ctest-failed.log \\; || true
                        find build -path "*/Testing/Temporary/*" -name "*.log" -exec cp {} test-logs/ \\; || true
                        find build -name "*test*.log" -exec cp {} test-logs/ \\; || true
                    '''
                }
                archiveArtifacts artifacts: 'test-logs/**',
                allowEmptyArchive: true
            }
        }
        stage('RPC Tests') {
            steps {
                sh '''
                    export FIROD="$(pwd)/build/bin/firod"
                    export FIROCLI="$(pwd)/build/bin/firo-cli"
                    qa/pull-tester/rpc-tests.py -extended
                '''
            }
        }
        stage('Archive Binaries') {
            steps {
                script {
                    sh '''
                        mkdir -p artifacts
                        cp build/bin/firo* artifacts/ || true
                    '''
                }
                archiveArtifacts artifacts: 'artifacts/**',
                allowEmptyArchive: true
            }
        }
    }
}
