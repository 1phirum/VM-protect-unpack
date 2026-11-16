#include "main_window.h"
#include "query_result.h"
#include <QDateTime>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QLabel>
#include <QSpinBox>
#include <QStatusBar>
#include <QtConcurrent>

static QString hexValue(quint64 value)
{
    return "0x" + QString::number(value, 16).toUpper().rightJustified(8, '0');
}

void MainWindow::readMemory()
{
    if (!pid_)
    {
        pages_["Hex editor"]->setMessage("Attach to a process before reading memory.");
        return;
    }
    bool valid = false;
    const QString text = address_->text().trimmed();
    const quint64 address =
        text.toULongLong(&valid, text.startsWith("0x", Qt::CaseInsensitive) ? 16 : 10);
    if (!valid)
    {
        pages_["Hex editor"]->setMessage("Enter a valid address.");
        return;
    }
    const quint32 pid = pid_;
    const int requested = readSize_->value();
    const quint64 revision = sessionRevision_;
    struct ReadResult
    {
        QByteArray bytes;
        QString error;
    };
    ++pendingInspections_;
    auto* watcher = new QFutureWatcher<ReadResult>(this);
    connect(watcher, &QFutureWatcher<ReadResult>::finished, this,
            [this, watcher, address, requested, revision]
            {
                ReadResult result = watcher->result();
                watcher->deleteLater();
                --pendingInspections_;
                if (revision != sessionRevision_)
                {
                    return;
                }
                QList<QStringList> rows;
                for (int offset = 0; offset < result.bytes.size(); offset += 16)
                {
                    const QByteArray bytes = result.bytes.mid(offset, 16);
                    QStringList hex;
                    QString ascii;
                    for (unsigned char byte : bytes)
                    {
                        hex.append(QString::number(byte, 16).rightJustified(2, '0').toUpper());
                        ascii.append(byte >= 32 && byte < 127 ? QChar(byte) : QChar('.'));
                    }
                    rows.append({hexValue(address + offset), hex.join(' '), ascii});
                }
                pages_["Hex editor"]->setRecords({"Address", "Hex bytes", "ASCII"}, rows);
                pages_["Hex editor"]->setMessage(QString::number(result.bytes.size()) + "/" +
                                                 QString::number(requested) + " bytes read. " +
                                                 result.error);
            });
    watcher->setFuture(QtConcurrent::run(
        [pid, address, requested]
        {
            ReadResult result;
            result.bytes.resize(requested);
            size_t got = 0;
            vp_error error{};
            if (vp_read(pid, address, result.bytes.data(), requested, &got, &error) != 0)
            {
                result.error = QString::fromWCharArray(error.message);
            }
            result.bytes.resize(static_cast<qsizetype>(got));
            return result;
        }));
}
