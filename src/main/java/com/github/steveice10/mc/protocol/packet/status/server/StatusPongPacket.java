package com.github.steveice10.mc.protocol.packet.status.server;

import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
@AllArgsConstructor
public class StatusPongPacket implements Packet {
    private long pingTime;

    @Override
    public void read(NetInput in) throws IOException {
        this.pingTime = in.readLong();
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeLong(this.pingTime);
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
