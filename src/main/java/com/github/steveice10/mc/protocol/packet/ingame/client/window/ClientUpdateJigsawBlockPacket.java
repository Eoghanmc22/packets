package com.github.steveice10.mc.protocol.packet.ingame.client.window;

import com.github.steveice10.mc.protocol.data.game.entity.metadata.Position;
import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
@AllArgsConstructor
public class ClientUpdateJigsawBlockPacket implements Packet {
    private @NonNull Position position;
    private @NonNull String name;
    private @NonNull String target;
    private @NonNull String pool;
    private @NonNull String finalState;
    private @NonNull String jointType;

    @Override
    public void read(NetInput in) throws IOException {
        this.position = Position.read(in);
        this.name = in.readString();
        this.target = in.readString();
        this.pool = in.readString();
        this.finalState = in.readString();
        this.jointType = in.readString();
    }

    @Override
    public void write(NetOutput out) throws IOException {
        Position.write(out, this.position);
        out.writeString(this.name);
        out.writeString(this.target);
        out.writeString(this.pool);
        out.writeString(this.finalState);
        out.writeString(this.jointType);
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
