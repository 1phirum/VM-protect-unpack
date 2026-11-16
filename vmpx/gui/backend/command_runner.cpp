#include "command_runner.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
CommandRunner::CommandRunner(QObject* p)
    : QObject(p), worker_(QCoreApplication::applicationDirPath() + "/vmpx.exe")
{
    process_.setProcessChannelMode(QProcess::MergedChannels);
    connect(&process_, &QProcess::started, this, [this] { emit started(command_); });
    connect(&process_, &QProcess::readyReadStandardOutput, this, [this] { drain(); });
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus status)
            {
                drain(true);
                if (!reported_)
                {
                    reported_ = true;
                    emit completed(command_, status == QProcess::NormalExit ? code : -1,
                                   cancelled_);
                }
            });
    connect(&process_, &QProcess::errorOccurred, this,
            [this](QProcess::ProcessError e)
            {
                emit output(process_.errorString());
                if (e == QProcess::FailedToStart && !reported_)
                {
                    reported_ = true;
                    emit completed(command_, -1, false);
                }
            });
}
bool CommandRunner::busy() const
{
    return process_.state() != QProcess::NotRunning;
}

CommandRunner::~CommandRunner()
{
    if (busy())
    {
        process_.kill();
        process_.waitForFinished(2000);
    }
}
QString CommandRunner::workerPath() const
{
    return worker_;
}
void CommandRunner::setWorkerPath(const QString& path)
{
    worker_ = path;
}
void CommandRunner::start(const QString& command, const QStringList& args)
{
    if (busy())
    {
        return;
    }
    command_ = command;
    ++generation_;
    cancelled_ = false;
    reported_ = false;
    pending_.clear();
    if (!QFileInfo::exists(worker_))
    {
        emit output("Backend worker missing: " + worker_);
        reported_ = true;
        emit completed(command, -1, false);
        return;
    }
    process_.setWorkingDirectory(QFileInfo(worker_).absolutePath());
    process_.setProgram(worker_);
    process_.setArguments(QStringList{command} + args);
    process_.start();
}
void CommandRunner::cancel()
{
    if (!busy())
    {
        return;
    }
    cancelled_ = true;
    const quint64 generation = generation_;
    process_.terminate();
    QTimer::singleShot(2000, this,
                       [this, generation]
                       {
                           if (generation == generation_ && cancelled_ && busy())
                           {
                               process_.kill();
                           }
                       });
}
void CommandRunner::drain(bool final)
{
    pending_ += process_.readAllStandardOutput();
    qsizetype split;
    while ((split = pending_.indexOf('\n')) >= 0)
    {
        QByteArray line = pending_.left(split);
        pending_.remove(0, split + 1);
        emit output(QString::fromLocal8Bit(line).trimmed());
    }
    if (pending_.size() > 1048576)
    {
        emit output(QString::fromLocal8Bit(pending_.left(1048576)));
        pending_.clear();
    }
    if (final && !pending_.isEmpty())
    {
        emit output(QString::fromLocal8Bit(pending_));
        pending_.clear();
    }
}
